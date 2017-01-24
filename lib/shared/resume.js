'use strict';

const uuid = require('uuid');
const url = require('url');
const _ = require('lodash');
const errors = require('../helpers/errors');
const instance = require('../helpers/weak_cache');

const j = JSON.parse;

module.exports = function getResumeAction(provider) {
  return function* resumeAction(next) {
    this.oidc.uuid = this.params.grant;

    const cookieOptions = _.omit(instance(provider).configuration('cookies.short'), 'maxAge', 'expires');

    try {
      this.query = j(this.cookies.get(provider.cookieName('resume'), cookieOptions));
    } catch (err) {
      throw new errors.InvalidRequestError('authorization request has expired');
    }

    const result = (() => {
      try {
        return j(this.cookies.get(provider.cookieName('interactionResult'), cookieOptions));
      } catch (err) {
        return {};
      }
    })();

    const clearOpts = Object.assign({}, cookieOptions);
    clearOpts.path = url.parse(this.oidc.urlFor('resume', { grant: this.oidc.uuid })).pathname;

    this.cookies.set(provider.cookieName('interactionResult'), null, clearOpts);
    this.cookies.set(provider.cookieName('resume'), null, clearOpts);

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
