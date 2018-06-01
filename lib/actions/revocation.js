const compose = require('koa-compose');
const debug = require('debug')('oidc-provider:revocation');

const PARAM_LIST = new Set(['token', 'token_type_hint']);

const { InvalidRequest } = require('../helpers/errors');
const presence = require('../helpers/validate_presence');
const instance = require('../helpers/weak_cache');
const authAndParams = require('../shared/token_auth');

const revokeable = ['AccessToken', 'ClientCredentials', 'RefreshToken'];

module.exports = function revocationAction(provider) {
  const { grantTypeHandlers } = instance(provider);

  function getAccessToken(token) {
    return provider.AccessToken.find(token);
  }

  function getClientCredentials(token) {
    /* istanbul ignore if */
    if (!grantTypeHandlers.has('client_credentials')) return undefined;
    return provider.ClientCredentials.find(token);
  }

  function getRefreshToken(token) {
    /* istanbul ignore if */
    if (!grantTypeHandlers.has('refresh_token')) return undefined;
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
      debug(
        'uuid=%s client=%s token=%s',
        ctx.oidc.uuid,
        ctx.oidc.client.clientId,
        ctx.oidc.params.token,
      );
      await next();
    },

    async function revokeToken(ctx, next) {
      let token;
      const { params } = ctx.oidc;

      switch (params.token_type_hint) {
        case 'access_token':
          token = await getAccessToken(params.token)
            .then((result) => {
              if (result) return result;
              return Promise.all([
                getClientCredentials(params.token),
                getRefreshToken(params.token),
              ]).then(findResult);
            });
          break;
        case 'client_credentials':
          token = await getClientCredentials(params.token)
            .then((result) => {
              if (result) return result;
              return Promise.all([
                getAccessToken(params.token),
                getRefreshToken(params.token),
              ]).then(findResult);
            });
          break;
        case 'refresh_token':
          token = await getRefreshToken(params.token)
            .then((result) => {
              if (result) return result;
              return Promise.all([
                getAccessToken(params.token),
                getClientCredentials(params.token),
              ]).then(findResult);
            });
          break;
        default:
          token = await Promise.all([
            getAccessToken(params.token),
            getClientCredentials(params.token),
            getRefreshToken(params.token),
          ]).then(findResult);
      }

      if (!token) return;

      if (revokeable.includes(token.kind)) {
        ctx.oidc.entity(token.kind, token);
      } else {
        return;
      }

      if (token.clientId !== ctx.oidc.client.clientId) {
        ctx.throw(new InvalidRequest('this token does not belong to you'));
      }

      await token.destroy();

      await next();
    },
  ]);
};
