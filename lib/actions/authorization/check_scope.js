'use strict';

const _ = require('lodash');
const errors = require('../../helpers/errors');

/*
 * Validates that all requested scopes are supported by the provider, that openid is amongst them
 * and that offline_access prompt is requested together with consent scope
 *
 * @throws: invalid_request
 */
module.exports = provider => function* checkScope(next) {
  const scopes = this.oidc.params.scope.split(' ');

  const unsupported = _.difference(scopes, provider.configuration('scopes'));
  this.assert(_.isEmpty(unsupported), new errors.InvalidRequestError(
    `invalid scope value(s) provided. (${unsupported.join(',')})`));

  this.assert(scopes.indexOf('openid') !== -1,
    new errors.InvalidRequestError('openid is required scope'));

  if (scopes.indexOf('offline_access') !== -1 && this.oidc.prompts.indexOf('consent') === -1) {
    this.throw(new errors.InvalidRequestError('offline_access scope requires consent prompt'));
  }

  yield next;
};
