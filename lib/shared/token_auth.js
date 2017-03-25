const errors = require('../helpers/errors');
const instance = require('../helpers/weak_cache');

const tokenCredentialAuth = require('./token_credential_auth');
const getAuthMiddleware = require('./token_jwt_auth');

module.exports = function tokenClientAuth(provider, endpoint) {
  const tokenJwtAuth = getAuthMiddleware(provider, endpoint);
  const pkce = instance(provider).configuration('features.pkce');

  return async function tokenAuth(ctx, next) {
    const params = ctx.oidc.params;
    let possibleSkip = pkce && pkce.skipClientAuth && ctx.oidc.client.applicationType === 'native';

    // if (possibleSkip && endpoint === 'revocation') {
    //   possibleSkip = true;
    // } else
    if (possibleSkip && endpoint === 'token') {
      possibleSkip = ctx.oidc.client.grantTypeAllowed(params.grant_type) &&
        ((params.grant_type === 'authorization_code' && params.code_verifier) ||
          params.grant_type === 'refresh_token');
    } else {
      possibleSkip = false;
    }

    switch (ctx.oidc.client.tokenEndpointAuthMethod) {
      case 'none':

        if (possibleSkip) {
          ctx.oidc.onlyPKCE = true;
          break;
        }

        ctx.throw(new errors.InvalidRequestError('client not supposed to access token endpoint'));

        /* istanbul ignore next */
        break;
      case 'client_secret_post':

        if (possibleSkip && !params.client_secret) {
          ctx.oidc.onlyPKCE = true;
          break;
        }


        ctx.assert(params.client_id, new errors.InvalidRequestError(
          'client_id must be provided in the body'));

        ctx.assert(params.client_secret, new errors.InvalidRequestError(
          'client_secret must be provided in the body'));

        tokenCredentialAuth(ctx, ctx.oidc.client.clientSecret, params.client_secret);

        break;
      case 'client_secret_jwt':

        await tokenJwtAuth(ctx, ctx.oidc.client.keystore,
          ctx.oidc.client.tokenEndpointAuthSigningAlg ?
            [ctx.oidc.client.tokenEndpointAuthSigningAlg] : ['HS256', 'HS384', 'HS512']);

        break;
      case 'private_key_jwt':

        await tokenJwtAuth(ctx, ctx.oidc.client.keystore,
          ctx.oidc.client.tokenEndpointAuthSigningAlg ?
            [ctx.oidc.client.tokenEndpointAuthSigningAlg] : ['ES256', 'ES384', 'ES512', 'RS256',
              'RS384', 'RS512', 'PS256', 'PS384', 'PS512']);

        break;
      default: { // client_secret_basic
        const auth = ctx.oidc.authorization;

        if (possibleSkip && !auth.clientSecret) {
          ctx.oidc.onlyPKCE = true;
          break;
        }

        ctx.assert(auth.clientId, new errors.InvalidRequestError(
          'client_id must be provided in the Authorization header'));

        ctx.assert(auth.clientSecret, new errors.InvalidRequestError(
          'client_secret must be provided in the Authorization header'));

        tokenCredentialAuth(ctx, ctx.oidc.client.clientSecret, auth.clientSecret);
      }
    }

    await next();
  };
};
