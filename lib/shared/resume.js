const uuid = require('uuid');
const url = require('url');
const _ = require('lodash');
const { InvalidRequestError } = require('../helpers/errors');
const instance = require('../helpers/weak_cache');

const j = JSON.parse;

module.exports = function getResumeAction(provider) {
  return async function resumeAction(ctx, next) {
    ctx.oidc.uuid = ctx.params.grant;

    const cookieOptions = _.omit(instance(provider).configuration('cookies.short'), 'maxAge', 'expires');

    try {
      ctx.query = j(ctx.cookies.get(provider.cookieName('resume'), cookieOptions));
    } catch (err) {
      throw new InvalidRequestError('authorization request has expired');
    }

    const result = (() => {
      try {
        return j(ctx.cookies.get(provider.cookieName('interactionResult'), cookieOptions));
      } catch (err) {
        return {};
      }
    })();

    const clearOpts = _.defaults({}, cookieOptions, {
      path: url.parse(ctx.oidc.urlFor('resume', { grant: ctx.oidc.uuid })).pathname,
    });

    ctx.cookies.set(provider.cookieName('interactionResult'), null, clearOpts);
    ctx.cookies.set(provider.cookieName('resume'), null, clearOpts);

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

    ctx.oidc.result = result;

    await next();
  };
};
