'use strict';

const base64url = require('base64url').decode;
const errors = require('../helpers/errors');

module.exports = function* findClientId(next) {
  this.oidc.authorization = {};
  const params = this.oidc.params;

  if (this.headers.authorization) { // client_secret_basic
    const parts = this.headers.authorization.split(' ');
    this.assert(parts.length === 2 && parts[0] === 'Basic',
      new errors.InvalidRequestError('invalid authorization header value format'));

    const basic = new Buffer(parts[1], 'base64').toString('utf8');
    const i = basic.indexOf(':');

    this.assert(i !== -1,
      new errors.InvalidRequestError('invalid authorization header value format'));

    this.oidc.authorization.clientId = basic.slice(0, i);
    this.oidc.authorization.clientSecret = basic.slice(i + 1);
  } else if (params.client_id && !params.client_assertion) { // client_secret_post
    this.oidc.authorization.clientId = params.client_id;
  } else if (params.client_assertion) { // client_secret_jwt and private_key_jwt
    const assertionSub = (() => {
      try {
        return JSON.parse(base64url(params.client_assertion.split('.')[1])).sub;
      } catch (err) {
        return this.throw(new errors.InvalidRequestError('invalid client_assertion'));
      }
    })();

    this.assert(!params.client_id || assertionSub === params.client_id,
      new errors.InvalidRequestError('subject of client_assertion must be the same as client_id'));

    this.oidc.authorization.clientId = assertionSub;
  }

  this.assert(this.oidc.authorization.clientId,
    new errors.InvalidClientError('no client authentication mechanism provided'));

  yield next;
};
