const url = require('url');

const omit = require('lodash/omit');
const upperFirst = require('lodash/upperFirst');
const camelCase = require('lodash/camelCase');
const isObjectLike = require('lodash/isObjectLike');

const nanoid = require('../../helpers/nanoid');
const errors = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');
const Params = require('../../helpers/params');
const formPost = require('../../response_modes/form_post');

module.exports = async function resumeAction(whitelist, resumeRouteName, ctx, next) {
  const cookieOptions = omit(
    instance(ctx.oidc.provider).configuration('cookies.short'),
    'maxAge',
    'expires',
  );

  const cookieId = ctx.oidc.cookies.get(ctx.oidc.provider.cookieName('resume'), cookieOptions);
  if (!cookieId || cookieId !== ctx.oidc.uid) {
    throw new errors.SessionNotFound('authorization request has expired');
  }

  const interactionSession = await ctx.oidc.provider.Interaction.find(cookieId);
  if (!interactionSession) {
    throw new errors.SessionNotFound('interaction session not found');
  }

  const {
    result,
    params: storedParams = {},
    signed = [],
  } = interactionSession;

  if (
    result
    && result.login
    && ctx.oidc.session.account
    && ctx.oidc.session.account !== result.login.account
  ) {
    ctx.oidc.session.state = {
      secret: nanoid(),
      clientId: storedParams.client_id,
      postLogoutRedirectUri: ctx.oidc.urlFor(ctx.oidc.route, ctx.params),
    };

    await formPost(ctx, ctx.oidc.urlFor('end_session_confirm'), {
      xsrf: ctx.oidc.session.state.secret,
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
  ctx.oidc.cookies.set(ctx.oidc.provider.cookieName('resume'), null, clearOpts);

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
  const { session } = ctx.oidc;

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

  if (result && isObjectLike(result.meta)) {
    session.metaFor(params.client_id, result.meta);
  }

  ctx.oidc.result = result;

  if (!session.new) {
    session.resetIdentifier();
  }

  await next();
};
