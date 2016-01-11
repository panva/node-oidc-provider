'use strict';

let base64url = require('base64url');
let errors = require('../helpers/errors');

module.exports = function * findClientId(next) {

  this.oidc.authorization = {};

  if (this.headers.authorization) {
    this.assert(!this.oidc.params.client_id,
      new errors.InvalidRequestError(
        'combining multiple client authentication mechanism is no good'));

    let parts = this.headers.authorization.split(' ');
    this.assert(parts.length === 2 && parts[0] === 'Basic',
      new errors.InvalidRequestError(
        'invalid authorization header value format'));

    let basic = new Buffer(parts[1], 'base64').toString('utf8');
    let i = basic.indexOf(':');

    this.assert(i !== -1,
      new errors.InvalidRequestError(
        'invalid authorization header value format'));

    this.oidc.authorization.clientId = basic.slice(0, i);
    this.oidc.authorization.clientSecret = basic.slice(i + 1);
  } else if (this.oidc.params.client_id && !this.oidc.params.client_assertion) {
    this.oidc.authorization.clientId = this.oidc.params.client_id;
  } else if (this.oidc.params.client_assertion) {

    let assertionSub;

    try {
      assertionSub = JSON.parse(
        base64url.decode(this.oidc.params.client_assertion.split('.')[1])
      ).sub;
    } catch (err) {}

    this.assert(!this.oidc.params.client_id ||
      assertionSub === this.oidc.params.client_id,
      new errors.InvalidRequestError(
        'subject of client_assertion must be the same as client_id'));

    this.oidc.authorization.clientId = assertionSub;
  }

  this.assert(this.oidc.authorization.clientId,
    new errors.InvalidClientError(
      'no client authentication mechanism provided'));

  yield next;
};
