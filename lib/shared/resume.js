const assert = require('assert');
const createError = require('http-errors');
const uuid = require('uuid/v4');
const url = require('url');
const _ = require('lodash');
const { InvalidRequestError } = require('../helpers/errors');
const instance = require('../helpers/weak_cache');

module.exports = function getResumeAction(provider) {
  return async function resumeAction(ctx, next) {
    ctx.oidc.uuid = ctx.params.grant;

    const cookieOptions = _.omit(instance(provider).configuration('cookies.short'), 'maxAge', 'expires');

    const cookieId = ctx.cookies.get(provider.cookieName('resume'), cookieOptions);
    if (!cookieId || cookieId !== ctx.oidc.uuid) {
      ctx.throw(new InvalidRequestError('authorization request has expired'));
    }

    const interactionSession = await provider.Session.find(cookieId);
    ctx.assert(interactionSession, new InvalidRequestError('interaction session not found'));

    const { result = {}, params = {}, signed = [] } = interactionSession;
    await interactionSession.destroy();

    ctx.query = params;
    ctx.oidc.signed = signed;

    const clearOpts = _.defaults({}, cookieOptions, {
      path: url.parse(ctx.oidc.urlFor('resume', { grant: ctx.oidc.uuid })).pathname,
    });
    ctx.cookies.set(provider.cookieName('resume'), null, clearOpts);

    if (result.error) {
      assert(!result.login, 'login shouldn\'t be provided with an error result');
      assert(!result.consent, 'consent shouldn\'t be provided with an error result');
      assert(typeof result.error === 'string', 'error should be a string');

      const description = result.error_description
        ? { error_description: result.error_description }
        : undefined;
      const err = createError(400, result.error, description);

      ctx.throw(err);
    }

    if (result.login) {
      if (!result.login.remember) ctx.oidc.session.transient = true;

      if (ctx.oidc.session.account !== result.login.account) {
        delete ctx.oidc.session.authorizations;
      }

      ctx.oidc.session.account = result.login.account;
      ctx.oidc.session.loginTs = result.login.ts;
    }

    if (result.consent && result.consent.scope !== undefined) {
      ctx.query.scope = String(result.consent.scope);
    }

    if (!_.isEmpty(result) && !ctx.oidc.session.sidFor(ctx.query.client_id)) {
      ctx.oidc.session.sidFor(ctx.query.client_id, uuid());
    }

    if (!_.isEmpty(result) && _.isObjectLike(result.meta)) {
      ctx.oidc.session.metaFor(ctx.query.client_id, result.meta);
    }

    ctx.oidc.result = result;

    await next();
  };
};
