'use strict';

const errors = require('../helpers/errors');

const tokenCredentialAuth = require('./token_credential_auth');
const getAuthMiddleware = require('./token_jwt_auth');

module.exports = function tokenClientAuth(provider) {
  const tokenJwtAuth = getAuthMiddleware(provider);

  return function * tokenAuth(next) {
    switch (this.oidc.client.tokenEndpointAuthMethod) {
      case 'none':

        this.throw(new errors.InvalidRequestError(
        'client not supposed to access token endpoint'));

        /* istanbul ignore next */
        break;
      case 'client_secret_post': {
        const params = this.oidc.params;

        this.assert(params.client_id, new errors.InvalidRequestError(
          'client_id must be provided in the body'));

        this.assert(params.client_secret, new errors.InvalidRequestError(
          'client_secret must be provided in the body'));

        yield tokenCredentialAuth.call(this, this.oidc.client.clientSecret,
          params.client_secret);

        break;
      }
      case 'client_secret_jwt':

        yield tokenJwtAuth.call(this, this.oidc.client.keystore,
        this.oidc.client.tokenEndpointAuthSigningAlg ?
          [this.oidc.client.tokenEndpointAuthSigningAlg] : ['HS256', 'HS384',
            'HS512']);

        break;
      case 'private_key_jwt':

        yield tokenJwtAuth.call(this, this.oidc.client.keystore,
        this.oidc.client.tokenEndpointAuthSigningAlg ?
          [this.oidc.client.tokenEndpointAuthSigningAlg] : ['ES256', 'ES384',
            'ES512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512']);

        break;
      default: { // Client_secret_basic
        const auth = this.oidc.authorization;

        this.assert(auth.clientId, new errors.InvalidRequestError(
          'client_id must be provided in the Authorization header'));

        this.assert(auth.clientSecret, new errors.InvalidRequestError(
          'client_secret must be provided in the Authorization header'));

        yield tokenCredentialAuth.call(this, this.oidc.client.clientSecret,
          auth.clientSecret);
      }
    }

    yield next;
  };
};
