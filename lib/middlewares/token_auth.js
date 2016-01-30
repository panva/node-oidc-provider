'use strict';

let errors = require('../helpers/errors');

let tokenCredentialAuth = require('./token_credential_auth');

module.exports = function(provider) {
  let tokenJwtAuth = require('./token_jwt_auth')(provider);

  return function * tokenAuth(next) {
    switch (this.oidc.client.tokenEndpointAuthMethod) {
    case 'none':

      this.throw(new errors.InvalidRequestError(
        'client not supposed to access token endpoint'));

      break;
    case 'client_secret_post':
      let params = this.oidc.params;

      this.assert(params.client_id, new errors.InvalidRequestError(
        'client_id must be provided in the body'));

      this.assert(params.client_secret, new errors.InvalidRequestError(
        'client_secret must be provided in the body'));

      yield tokenCredentialAuth.call(this, this.oidc.client.clientSecret,
        params.client_secret);

      break;
    case 'client_secret_jwt':

      yield tokenJwtAuth.call(this, this.oidc.client.keystore,
        ['HS256', 'HS384', 'HS512']);

      break;
    case 'private_key_jwt':

      yield tokenJwtAuth.call(this, this.oidc.client.keystore, ['ES256',
      'ES384', 'ES512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512']);

      break;
    default: // Client_secret_basic

      yield tokenCredentialAuth.call(this, this.oidc.client.clientSecret,
        this.oidc.authorization.clientSecret);
    }

    yield next;
  };
};
