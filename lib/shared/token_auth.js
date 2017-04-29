const { InvalidRequestError } = require('../helpers/errors');

const tokenCredentialAuth = require('./token_credential_auth');
const getAuthMiddleware = require('./token_jwt_auth');

module.exports = function tokenClientAuth(provider, endpoint) {
  const tokenJwtAuth = getAuthMiddleware(provider, endpoint);

  return async function tokenAuth(ctx, next) {
    const { params } = ctx.oidc;

    switch (ctx.oidc.client[`${endpoint}EndpointAuthMethod`]) {
      case 'none':
        break;
      case 'client_secret_post':

        ctx.assert(params.client_id, new InvalidRequestError(
          'client_id must be provided in the body'));

        ctx.assert(params.client_secret, new InvalidRequestError(
          'client_secret must be provided in the body'));

        tokenCredentialAuth(ctx, ctx.oidc.client.clientSecret, params.client_secret);

        break;
      case 'client_secret_jwt':

        await tokenJwtAuth(ctx, ctx.oidc.client.keystore,
          ctx.oidc.client[`${endpoint}EndpointAuthSigningAlg`] ?
            [ctx.oidc.client[`${endpoint}EndpointAuthSigningAlg`]] : ['HS256', 'HS384', 'HS512']);

        break;
      case 'private_key_jwt':

        await tokenJwtAuth(ctx, ctx.oidc.client.keystore,
          ctx.oidc.client[`${endpoint}EndpointAuthSigningAlg`] ?
            [ctx.oidc.client[`${endpoint}EndpointAuthSigningAlg`]] : ['ES256', 'ES384', 'ES512', 'RS256',
              'RS384', 'RS512', 'PS256', 'PS384', 'PS512']);

        break;
      default: { // client_secret_basic
        const auth = ctx.oidc.authorization;

        ctx.assert(auth.clientId, new InvalidRequestError(
          'client_id must be provided in the Authorization header'));

        ctx.assert(auth.clientSecret, new InvalidRequestError(
          'client_secret must be provided in the Authorization header'));

        tokenCredentialAuth(ctx, ctx.oidc.client.clientSecret, auth.clientSecret);
      }
    }

    await next();
  };
};
