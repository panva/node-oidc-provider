const url = require('url');

const upperFirst = require('../../helpers/_/upper_first');
const camelCase = require('../../helpers/_/camel_case');
const nanoid = require('../../helpers/nanoid');
const errors = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');
const Params = require('../../helpers/params');
const formPost = require('../../response_modes/form_post');
const ssHandler = require('../../helpers/samesite_handler');
const epochTime = require('../../helpers/epoch_time');

module.exports = async function resumeAction(allowLisst, resumeRouteName, ctx, next) {
  const cookieOptions = instance(ctx.oidc.provider).configuration('cookies.short');

  const cookieId = ssHandler.get(
    ctx.oidc.cookies,
    ctx.oidc.provider.cookieName('resume'),
    cookieOptions,
  );

  if (!cookieId) {
    throw new errors.SessionNotFound('authorization request has expired');
  }

  const interactionSession = await ctx.oidc.provider.Interaction.find(cookieId);
  if (!interactionSession) {
    throw new errors.SessionNotFound('interaction session not found');
  }
  ctx.oidc.entity('Interaction', interactionSession);

  if (cookieId !== interactionSession.uid) {
    throw new errors.SessionNotFound('authorization session and cookie identifier mismatch');
  }

  const {
    result,
    params: storedParams = {},
    trusted = [],
    session: originSession,
  } = interactionSession;

  const { session } = ctx.oidc;

  if (originSession && originSession.uid && originSession.uid !== session.uid) {
    throw new errors.SessionNotFound('interaction session and authentication session mismatch');
  }

  if (
    result
    && result.login
    && session.accountId
    && session.accountId !== result.login.accountId
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

  const params = new (Params(allowLisst))(storedParams);
  ctx.oidc.params = params;
  ctx.oidc.trusted = trusted;
  ctx.oidc.redirectUriCheckPerformed = true;

  const clearOpts = {
    ...cookieOptions,
    path: url.parse(ctx.oidc.urlFor(resumeRouteName, { uid: interactionSession.uid })).pathname,
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
    }
    throw new errors.CustomOIDCProviderError(result.error, result.error_description);
  }

  if (result && result.login) {
    const {
      remember = true, accountId, ts: loginTs, amr, acr,
    } = result.login;

    session.loginAccount({
      accountId, loginTs, amr, acr, transient: !remember,
    });
  }

  ctx.oidc.result = result;

  if (!session.new) {
    session.resetIdentifier();
  }

  await next();
};
