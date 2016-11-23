'use strict';

const uuid = require('uuid');
const _ = require('lodash');
const errors = require('../helpers/errors');
const instance = require('../helpers/weak_cache');

const j = JSON.parse;

module.exports = function getResumeAction(provider) {
  return async function resumeAction(ctx, next) {
    ctx.oidc.uuid = ctx.params.grant;

    const cookieOptions = instance(provider).configuration('cookies.short');

    try {
      ctx.query = j(ctx.cookies.get('_grant', cookieOptions));
    } catch (err) {
      throw new errors.InvalidRequestError('authorization request has expired');
    }

    const result = (() => {
      try {
        return j(ctx.cookies.get('_grant_result', cookieOptions));
      } catch (err) {
        return {};
      }
    })();
    ctx.cookies.set('_grant_result', null, cookieOptions);

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
