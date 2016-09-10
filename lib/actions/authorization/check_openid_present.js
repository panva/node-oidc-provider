'use strict';

const errors = require('../../helpers/errors');

/*
 * Checks openid presence amongst the requested scopes
 *
 * @throws: invalid_request
 */
module.exports = function* checkOpenIdPresent(next) {
  const scopes = this.oidc.params.scope.split(' ');

  this.assert(scopes.indexOf('openid') !== -1,
    new errors.InvalidRequestError('openid is required scope'));

  yield next;
};
