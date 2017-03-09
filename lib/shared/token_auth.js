'use strict';

const errors = require('../helpers/errors');
const instance = require('../helpers/weak_cache');

const tokenCredentialAuth = require('./token_credential_auth');
const getAuthMiddleware = require('./token_jwt_auth');

module.exports = function tokenClientAuth(provider, endpoint) {
  const tokenJwtAuth = getAuthMiddleware(provider, endpoint);
  const pkce = instance(provider).configuration('features.pkce');

  return function* tokenAuth(next) {
    const params = this.oidc.params;
    let possibleSkip = pkce && pkce.skipClientAuth && this.oidc.client.applicationType === 'native';

    // if (possibleSkip && endpoint === 'revocation') {
    //   possibleSkip = true;
    // } else
    if (possibleSkip && endpoint === 'token') {
      possibleSkip = this.oidc.client.grantTypeAllowed(params.grant_type) &&
        ((params.grant_type === 'authorization_code' && params.code_verifier) ||
          params.grant_type === 'refresh_token');
    } else {
      possibleSkip = false;
    }

    switch (this.oidc.client.tokenEndpointAuthMethod) {
      case 'none':

        if (possibleSkip) {
          this.oidc.onlyPKCE = true;
          break;
        }

        this.throw(new errors.InvalidRequestError('client not supposed to access token endpoint'));

        /* istanbul ignore next */
        break;
      case 'client_secret_post':

        if (possibleSkip && !params.client_secret) {
          this.oidc.onlyPKCE = true;
          break;
        }

        this.assert(params.client_id, new errors.InvalidRequestError(
          'client_id must be provided in the body'));

        this.assert(params.client_secret, new errors.InvalidRequestError(
          'client_secret must be provided in the body'));

        tokenCredentialAuth.call(this, this.oidc.client.clientSecret, params.client_secret);

        break;
      case 'client_secret_jwt':

        yield tokenJwtAuth.call(this, this.oidc.client.keystore,
          this.oidc.client.tokenEndpointAuthSigningAlg ?
            [this.oidc.client.tokenEndpointAuthSigningAlg] : ['HS256', 'HS384', 'HS512']);

        break;
      case 'private_key_jwt':

        yield tokenJwtAuth.call(this, this.oidc.client.keystore,
          this.oidc.client.tokenEndpointAuthSigningAlg ?
            [this.oidc.client.tokenEndpointAuthSigningAlg] : ['ES256', 'ES384', 'ES512', 'RS256',
              'RS384', 'RS512', 'PS256', 'PS384', 'PS512']);

        break;
      default: { // client_secret_basic
        const auth = this.oidc.authorization;

        if (possibleSkip && !auth.clientSecret) {
          this.oidc.onlyPKCE = true;
          break;
        }

        this.assert(auth.clientId, new errors.InvalidRequestError(
          'client_id must be provided in the Authorization header'));

        this.assert(auth.clientSecret, new errors.InvalidRequestError(
          'client_secret must be provided in the Authorization header'));

        tokenCredentialAuth.call(this, this.oidc.client.clientSecret, auth.clientSecret);
      }
    }

    yield next;
  };
};
