const Debug = require('debug');

const debug = new Debug('oidc-provider:revocation');
const uidToGrantId = new Debug('oidc-provider:uid');

const { InvalidRequest } = require('../helpers/errors');
const presence = require('../helpers/validate_presence');
const instance = require('../helpers/weak_cache');
const getTokenAuth = require('../shared/token_auth');
const { urlencoded: parseBody } = require('../shared/selective_body');
const rejectDupes = require('../shared/reject_dupes');
const paramsMiddleware = require('../shared/assemble_params');
const revokeGrant = require('../helpers/revoke_grant');

const revokeable = new Set(['AccessToken', 'ClientCredentials', 'RefreshToken']);

module.exports = function revocationAction(provider) {
  const { params: authParams, middleware: tokenAuth } = getTokenAuth(provider, 'revocation');
  const PARAM_LIST = new Set(['token', 'token_type_hint', ...authParams]);
  const { grantTypeHandlers } = instance(provider);

  function getAccessToken(token) {
    return provider.AccessToken.find(token);
  }

  function getClientCredentials(token) {
    /* istanbul ignore if */
    if (!grantTypeHandlers.has('client_credentials')) {
      return undefined;
    }
    return provider.ClientCredentials.find(token);
  }

  function getRefreshToken(token) {
    /* istanbul ignore if */
    if (!grantTypeHandlers.has('refresh_token')) {
      return undefined;
    }
    return provider.RefreshToken.find(token);
  }

  function findResult(results) {
    return results.find((found) => !!found);
  }

  return [
    parseBody,
    paramsMiddleware.bind(undefined, PARAM_LIST),
    ...tokenAuth,
    rejectDupes.bind(undefined, {}),

    async function validateTokenPresence(ctx, next) {
      presence(ctx, 'token');
      await next();
    },

    async function renderTokenResponse(ctx, next) {
      ctx.status = 200;
      ctx.body = '';
      await next();
      debug(
        'uid=%s client=%s token=%s',
        ctx.oidc.uid,
        ctx.oidc.client.clientId,
        ctx.oidc.params.token,
      );
    },

    async function revokeToken(ctx, next) {
      let token;
      const { params } = ctx.oidc;

      switch (params.token_type_hint) {
        case 'access_token':
        case 'urn:ietf:params:oauth:token-type:access_token':
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
        case 'urn:ietf:params:oauth:token-type:refresh_token':
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
        uidToGrantId('switched from uid=%s to value of grantId=%s', ctx.oidc.uid, token.grantId);
        ctx.oidc.uid = token.grantId;
      }

      if (token.clientId !== ctx.oidc.client.clientId) {
        throw new InvalidRequest('this token does not belong to you');
      }

      await token.destroy();

      if (token.kind === 'RefreshToken') {
        await revokeGrant(provider, ctx.oidc.client, token.grantId);
        provider.emit('grant.revoked', ctx, token.grantId);
      }

      await next();
    },
  ];
};
