const url = require('url');

const uuid = require('uuid/v4');
const _ = require('lodash');

const { SessionNotFound } = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');
const getParams = require('../../helpers/params');

module.exports = function getResumeAction(provider, whitelist, resumeRouteName) {
  const Params = getParams(whitelist);
  return async function resumeAction(ctx, next) {
    const cookieOptions = _.omit(instance(provider).configuration('cookies.short'), 'maxAge', 'expires');

    const cookieId = ctx.cookies.get(provider.cookieName('resume'), cookieOptions);
    if (!cookieId || cookieId !== ctx.oidc.uuid) {
      throw new SessionNotFound('authorization request has expired');
    }

    const interactionSession = await provider.Session.find(cookieId, { upsert: false });
    if (!interactionSession) {
      throw new SessionNotFound('interaction session not found');
    }

    const {
      result,
      params = {},
      signed = [],
    } = interactionSession;

    await interactionSession.destroy();

    ctx.oidc.params = new Params(params);
    ctx.oidc.signed = signed;
    ctx.oidc.redirectUriCheckPerformed = true;

    const clearOpts = _.defaults({}, cookieOptions, {
      path: url.parse(ctx.oidc.urlFor(resumeRouteName, {
        grant: ctx.oidc.uuid,
        ...(ctx.params.user_code ? { user_code: ctx.params.user_code } : undefined),
      })).pathname,
    });
    ctx.cookies.set(provider.cookieName('resume'), null, clearOpts);

    if (result && result.error) {
      ctx.throw(400, result.error, {
        error_description: result.error_description,
      });
    }

    if (result && result.login) {
      if (!result.login.remember) ctx.oidc.session.transient = true;

      if (ctx.oidc.session.account !== result.login.account) {
        delete ctx.oidc.session.authorizations;
      }

      ctx.oidc.session.account = result.login.account;
      ctx.oidc.session.loginTs = result.login.ts;
    }

    if (result && result.consent && result.consent.scope !== undefined) {
      ctx.oidc.params.scope = String(result.consent.scope);
    }

    if (!_.isEmpty(result) && !ctx.oidc.session.sidFor(ctx.oidc.params.client_id)) {
      ctx.oidc.session.sidFor(ctx.oidc.params.client_id, uuid());
    }

    if (!_.isEmpty(result) && _.isObjectLike(result.meta)) {
      ctx.oidc.session.metaFor(ctx.oidc.params.client_id, result.meta);
    }

    ctx.oidc.result = result;

    await next();
  };
};
