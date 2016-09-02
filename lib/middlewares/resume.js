'use strict';

const uuid = require('uuid').v4;
const _ = require('lodash');
const errors = require('../helpers/errors');

const j = JSON.parse;

module.exports = function getResumeAction(provider) {
  return function * resumeAction(next) {
    this.oidc.uuid = this.params.grant;

    const cookieOptions = provider.configuration('cookies.short');

    try {
      this.query = j(this.cookies.get('_grant', cookieOptions));
    } catch (err) {
      throw new errors.InvalidRequestError('authorization request has expired');
    }

    let result;
    try {
      result = j(this.cookies.get('_grant_result', cookieOptions));
    } catch (err) {
      result = {};
    }

    if (result.login) {
      if (!result.login.remember) {
        this.oidc.session.transient = true;
      }

      if (this.oidc.session.account !== result.login.account) {
        delete this.oidc.session.authorizations;
      }

      this.oidc.session.acrValue = result.login.acr;
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
