const Debug = require('debug');

const debug = new Debug('oidc-provider:revocation');
const uuidToGrantId = new Debug('oidc-provider:uuid');

const { InvalidRequest } = require('../helpers/errors');
const presence = require('../helpers/validate_presence');
const instance = require('../helpers/weak_cache');
const getTokenAuth = require('../shared/token_auth');
const bodyParser = require('../shared/selective_body');
const rejectDupes = require('../shared/reject_dupes');
const getParams = require('../shared/assemble_params');

const revokeable = new Set(['AccessToken', 'ClientCredentials', 'RefreshToken']);

module.exports = function revocationAction(provider) {
  const parseBody = bodyParser('application/x-www-form-urlencoded');
  const { params: authParams, middleware: tokenAuth } = getTokenAuth(provider, 'revocation');
  const PARAM_LIST = new Set(['token', 'token_type_hint', ...authParams]);
  const buildParams = getParams(PARAM_LIST);
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

  return [
    parseBody,
    buildParams,
    ...tokenAuth,
    rejectDupes,

    async function validateTokenPresence(ctx, next) {
      presence(ctx, 'token');
      await next();
    },

    async function renderTokenResponse(ctx, next) {
      ctx.status = 200;
      ctx.body = '';
      await next();
      debug(
        'uuid=%s client=%s token=%s',
        ctx.oidc.uuid,
        ctx.oidc.client.clientId,
        ctx.oidc.params.token,
      );
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

      if (revokeable.has(token.kind)) {
        ctx.oidc.entity(token.kind, token);
      } else {
        return;
      }

      if (token.grantId) {
        uuidToGrantId('switched from uuid=%s to value of grantId=%s', ctx.oidc.uuid, token.grantId);
        ctx.oidc.uuid = token.grantId;
      }

      if (token.clientId !== ctx.oidc.client.clientId) {
        throw new InvalidRequest('this token does not belong to you');
      }

      await token.destroy();

      await next();
    },
  ];
};
