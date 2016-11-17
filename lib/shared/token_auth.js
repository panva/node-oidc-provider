'use strict';

const errors = require('../helpers/errors');

const tokenCredentialAuth = require('./token_credential_auth');
const getAuthMiddleware = require('./token_jwt_auth');

module.exports = function tokenClientAuth(provider) {
  const tokenJwtAuth = getAuthMiddleware(provider);

  return async function tokenAuth(ctx, next) {
    switch (ctx.oidc.client.tokenEndpointAuthMethod) {
      case 'none':

        ctx.throw(new errors.InvalidRequestError('client not supposed to access token endpoint'));

        /* istanbul ignore next */
        break;
      case 'client_secret_post': {
        const params = ctx.oidc.params;

        ctx.assert(params.client_id, new errors.InvalidRequestError(
          'client_id must be provided in the body'));

        ctx.assert(params.client_secret, new errors.InvalidRequestError(
          'client_secret must be provided in the body'));

        tokenCredentialAuth.call(ctx, ctx.oidc.client.clientSecret, params.client_secret);

        break;
      }
      case 'client_secret_jwt':

        await tokenJwtAuth.call(ctx, ctx.oidc.client.keystore,
          ctx.oidc.client.tokenEndpointAuthSigningAlg ?
            [ctx.oidc.client.tokenEndpointAuthSigningAlg] : ['HS256', 'HS384', 'HS512']);

        break;
      case 'private_key_jwt':

        await tokenJwtAuth.call(ctx, ctx.oidc.client.keystore,
          ctx.oidc.client.tokenEndpointAuthSigningAlg ?
            [ctx.oidc.client.tokenEndpointAuthSigningAlg] : ['ES256', 'ES384', 'ES512', 'RS256',
              'RS384', 'RS512', 'PS256', 'PS384', 'PS512']);

        break;
      default: { // Client_secret_basic
        const auth = ctx.oidc.authorization;

        ctx.assert(auth.clientId, new errors.InvalidRequestError(
          'client_id must be provided in the Authorization header'));

        ctx.assert(auth.clientSecret, new errors.InvalidRequestError(
          'client_secret must be provided in the Authorization header'));

        tokenCredentialAuth.call(ctx, ctx.oidc.client.clientSecret, auth.clientSecret);
      }
    }

    await next();
  };
};
