const url = require('url');

const _ = require('lodash');

const nanoid = require('../../helpers/nanoid');
const errors = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');
const Params = require('../../helpers/params');
const formPost = require('../../response_modes/form_post');
const epochTime = require('../../helpers/epoch_time');

module.exports = async function resumeAction(whitelist, resumeRouteName, ctx, next) {
  const cookieOptions = _.omit(
    instance(ctx.oidc.provider).configuration('cookies.short'),
    'maxAge',
    'expires',
  );

  const cookieId = ctx.cookies.get(ctx.oidc.provider.cookieName('resume'), cookieOptions);
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
      postLogoutRedirectUri: ctx.href,
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
  ctx.cookies.set(ctx.oidc.provider.cookieName('resume'), null, clearOpts);

  if (result && result.error) {
    const className = _.upperFirst(_.camelCase(result.error));
    if (errors[className]) {
      throw new errors[className](result.error_description);
    } else {
      ctx.throw(400, result.error, {
        error_description: result.error_description,
      });
    }
  }
  const { session } = ctx.oidc;

  if (result && result.login) {
    const {
      remember = true, account, ts: loginTs = epochTime(), amr, acr,
    } = result.login;

    if (!remember) {
      session.transient = true;
    }

    Object.assign(session, {
      account, loginTs, amr, acr,
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

  if (!_.isEmpty(result)) {
    if (!session.sidFor(params.client_id)) {
      session.sidFor(params.client_id, nanoid());
    }

    if (!session.grantIdFor(params.client_id)) {
      session.grantIdFor(params.client_id, nanoid());
    }

    if (_.isObjectLike(result.meta)) {
      session.metaFor(params.client_id, result.meta);
    }
  }

  ctx.oidc.result = result;

  if (!session.new) {
    session.resetIdentifier();
  }

  await next();
};
