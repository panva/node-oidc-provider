const compose = require('koa-compose');
const debug = require('debug')('oidc-provider:revocation');

const PARAM_LIST = new Set(['token', 'token_type_hint']);

const { InvalidRequestError } = require('../helpers/errors');
const presence = require('../helpers/validate_presence');
const authAndParams = require('../shared/chains/client_auth');

module.exports = function revocationAction(provider) {
  function getAccessToken(token) {
    return provider.AccessToken.find(token);
  }

  function getClientCredentials(token) {
    return provider.ClientCredentials.find(token);
  }

  function getRefreshToken(token) {
    return provider.RefreshToken.find(token);
  }

  function findResult(results) {
    return results.find(found => !!found);
  }

  return compose([

    authAndParams(provider, PARAM_LIST, 'revocation'),

    async function validateTokenPresence(ctx, next) {
      presence(ctx, ['token']);
      await next();
    },

    async function renderTokenResponse(ctx, next) {
      ctx.status = 200;
      ctx.body = '';
      debug('uuid=%s client=%s token=%s',
        ctx.oidc.uuid,
        ctx.oidc.client.clientId,
        ctx.oidc.params.token);
      await next();
    },

    async function revokeToken(ctx, next) {
      let tryhard;
      const { params } = ctx.oidc;

      switch (params.token_type_hint) {
        case 'access_token':
          tryhard = getAccessToken(params.token)
            .then((result) => {
              if (result) return result;
              return Promise.all([
                getClientCredentials(params.token),
                getRefreshToken(params.token),
              ]).then(findResult);
            });
          break;
        case 'client_credentials':
          tryhard = getClientCredentials(params.token)
            .then((result) => {
              if (result) return result;
              return Promise.all([
                getAccessToken(params.token),
                getRefreshToken(params.token),
              ]).then(findResult);
            });
          break;
        case 'refresh_token':
          tryhard = getRefreshToken(params.token)
            .then((result) => {
              if (result) return result;
              return Promise.all([
                getAccessToken(params.token),
                getClientCredentials(params.token),
              ]).then(findResult);
            });
          break;
        default:
          tryhard = Promise.all([
            getAccessToken(params.token),
            getClientCredentials(params.token),
            getRefreshToken(params.token),
          ]).then(findResult);
      }

      let token;
      try {
        token = await tryhard;
      } catch (err) {
        if (err.message !== 'invalid_token') {
          throw err;
        }
      }

      if (!token) return;

      if (token.clientId !== ctx.oidc.client.clientId) {
        ctx.throw(new InvalidRequestError('this token does not belong to you'));
      }

      await token.destroy();

      await next();
    },
  ]);
};
