const Debug = require('debug');

const debug = new Debug('oidc-provider:introspection');
const uuidToGrantId = new Debug('oidc-provider:uuid');

const presence = require('../helpers/validate_presence');
const tokenAuth = require('../shared/token_auth');
const noCache = require('../shared/no_cache');
const mask = require('../helpers/claims');
const instance = require('../helpers/weak_cache');
const bodyParser = require('../shared/selective_body');
const rejectDupes = require('../shared/reject_dupes');
const getParams = require('../shared/assemble_params');

const introspectable = new Set(['AccessToken', 'ClientCredentials', 'RefreshToken']);
const PARAM_LIST = new Set(['token', 'token_type_hint', ...tokenAuth.AUTH_PARAMS]);

module.exports = function introspectionAction(provider) {
  const Claims = mask(instance(provider).configuration());
  const parseBody = bodyParser('application/x-www-form-urlencoded');
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
    noCache,
    parseBody,
    buildParams,
    ...tokenAuth(provider, 'introspection'),
    rejectDupes,

    async function validateTokenPresence(ctx, next) {
      presence(ctx, 'token');
      await next();
    },

    async function debugOutput(ctx, next) {
      await next();
      debug(
        'uuid=%s by client=%s token=%s response=%o',
        ctx.oidc.uuid,
        ctx.oidc.client.clientId,
        ctx.oidc.params.token, ctx.body,
      );
    },

    async function renderTokenResponse(ctx, next) {
      const { params } = ctx.oidc;

      ctx.body = { active: false };

      let token;

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

      if (!token || !token.isValid) {
        return;
      }
      if (token.grantId) {
        uuidToGrantId('switched from uuid=%s to value of grantId=%s', ctx.oidc.uuid, token.grantId);
        ctx.oidc.uuid = token.grantId;
      }

      if (ctx.oidc.client.introspectionEndpointAuthMethod === 'none') {
        if (token.clientId !== ctx.oidc.client.clientId) {
          return;
        }
      }

      if (introspectable.has(token.kind)) {
        ctx.oidc.entity(token.kind, token);
      } else {
        return;
      }

      if (token.clientId !== ctx.oidc.client.clientId) {
        ctx.body.sub = Claims.sub(
          token.accountId,
          (await provider.Client.find(token.clientId)).sectorIdentifier,
        );
      } else {
        ctx.body.sub = Claims.sub(token.accountId, ctx.oidc.client.sectorIdentifier);
      }

      Object.assign(ctx.body, {
        active: true,
        client_id: token.clientId,
        exp: token.exp,
        iat: token.iat,
        sid: token.sid,
        iss: token.iss,
        jti: token.jti,
        aud: token.aud,
        scope: token.scope,
      });

      await next();
    },
  ];
};
