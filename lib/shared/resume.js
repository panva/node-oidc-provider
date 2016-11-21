'use strict';

const uuid = require('uuid');
const _ = require('lodash');
const errors = require('../helpers/errors');
const instance = require('../helpers/weak_cache');

const j = JSON.parse;

module.exports = function getResumeAction(provider) {
  return function* resumeAction(next) {
    this.oidc.uuid = this.params.grant;

    const cookieOptions = instance(provider).configuration('cookies.short');

    try {
      this.query = j(this.cookies.get('_grant', cookieOptions));
    } catch (err) {
      throw new errors.InvalidRequestError('authorization request has expired');
    }

    const result = (() => {
      try {
        return j(this.cookies.get('_grant_result', cookieOptions));
      } catch (err) {
        return {};
      }
    })();
    this.cookies.set('_grant_result', null, cookieOptions);

    if (result.login) {
      if (!result.login.remember) this.oidc.session.transient = true;

      if (this.oidc.session.account !== result.login.account) {
        delete this.oidc.session.authorizations;
      }

      this.oidc.session.account = result.login.account;
      this.oidc.session.loginTs = result.login.ts;
    }

    if (result.consent && result.consent.scope !== undefined) {
      this.query.scope = String(result.consent.scope);
    }

    if (!_.isEmpty(result) && !this.oidc.session.sidFor(this.query.client_id)) {
      this.oidc.session.sidFor(this.query.client_id, uuid());
    }

    this.oidc.result = result;

    yield next;
  };
};
