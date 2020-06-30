const url = require('url');

const upperFirst = require('../../helpers/_/upper_first');
const isPlainObject = require('../../helpers/_/is_plain_object');
const camelCase = require('../../helpers/_/camel_case');
const nanoid = require('../../helpers/nanoid');
const errors = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');
const Params = require('../../helpers/params');
const formPost = require('../../response_modes/form_post');
const ssHandler = require('../../helpers/samesite_handler');
const epochTime = require('../../helpers/epoch_time');

module.exports = async function resumeAction(whitelist, resumeRouteName, ctx, next) {
  const { maxAge, expires, ...cookieOptions } = instance(ctx.oidc.provider).configuration('cookies.short');

  const cookieId = ssHandler.get(
    ctx.oidc.cookies,
    ctx.oidc.provider.cookieName('resume'),
    cookieOptions,
  );

  if (!cookieId || cookieId !== ctx.oidc.uid) {
    throw new errors.SessionNotFound('authorization request has expired');
  }

  const interactionSession = await ctx.oidc.provider.Interaction.find(cookieId);
  if (!interactionSession) {
    throw new errors.SessionNotFound('interaction session not found');
  }
  ctx.oidc.entity('Interaction', interactionSession);

  const {
    result,
    params: storedParams = {},
    signed = [],
    session: originSession,
  } = interactionSession;

  const { session } = ctx.oidc;

  if (originSession && originSession.uid && originSession.uid !== session.uid) {
    throw new errors.SessionNotFound('interaction session and authentication session mismatch');
  }

  if (
    result
    && result.login
    && session.account
    && session.account !== result.login.account
  ) {
    if (interactionSession.session && interactionSession.session.uid) {
      delete interactionSession.session.uid;
      await interactionSession.save(interactionSession.exp - epochTime());
    }

    session.state = {
      secret: nanoid(),
      clientId: storedParams.client_id,
      postLogoutRedirectUri: ctx.oidc.urlFor(ctx.oidc.route, ctx.params),
    };

    await formPost(ctx, ctx.oidc.urlFor('end_session_confirm'), {
      xsrf: session.state.secret,
      logout: 'yes',
    });

    return;
  }

  await interactionSession.destroy();

  const params = new (Params(whitelist))(storedParams);
  ctx.oidc.params = params;
  ctx.oidc.signed = signed;
  ctx.oidc.redirectUriCheckPerformed = true;

  const clearOpts = {
    ...cookieOptions,
    path: url.parse(ctx.oidc.urlFor(resumeRouteName, {
      uid: ctx.oidc.uid,
      ...(ctx.params.user_code ? { user_code: ctx.params.user_code } : undefined),
    })).pathname,
  };
  ssHandler.set(
    ctx.oidc.cookies,
    ctx.oidc.provider.cookieName('resume'),
    null,
    clearOpts,
  );

  if (result && result.error) {
    const className = upperFirst(camelCase(result.error));
    if (errors[className]) {
      throw new errors[className](result.error_description);
    } else {
      ctx.throw(400, result.error, {
        error_description: result.error_description,
      });
    }
  }

  session.ensureClientContainer(params.client_id);

  if (result && result.login) {
    const {
      remember = true, account, ts: loginTs, amr, acr,
    } = result.login;

    session.loginAccount({
      account, loginTs, amr, acr, transient: !remember,
    });
  }

  if (result && result.consent) {
    const {
      rejectedClaims,
      rejectedScopes,
      replace = false,
    } = result.consent;

    if (rejectedClaims) {
      session.rejectedClaimsFor(params.client_id, rejectedClaims, replace);
    }

    if (rejectedScopes) {
      session.rejectedScopesFor(params.client_id, rejectedScopes, replace);
    }

    session.promptedScopesFor(params.client_id, ctx.oidc.requestParamScopes);
    session.promptedClaimsFor(params.client_id, ctx.oidc.requestParamClaims);
  }

  if (result && isPlainObject(result.meta)) {
    session.metaFor(params.client_id, result.meta);
  }

  ctx.oidc.result = result;

  if (!session.new) {
    session.resetIdentifier();
  }

  await next();
};
