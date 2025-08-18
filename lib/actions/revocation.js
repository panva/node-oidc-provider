import presence from '../helpers/validate_presence.js';
import instance from '../helpers/weak_cache.js';
import getClientAuth from '../shared/client_auth.js';
import { urlencoded as parseBody } from '../shared/selective_body.js';
import rejectDupes from '../shared/reject_dupes.js';
import paramsMiddleware from '../shared/assemble_params.js';
import rejectStructuredTokens from '../shared/reject_structured_tokens.js';
import revoke from '../helpers/revoke.js';
import { checkAttestBinding } from '../helpers/check_attest_binding.js';

const revokeable = new Set(['AccessToken', 'ClientCredentials', 'RefreshToken']);

export default function revocationAction(provider) {
  const { params: authParams, middleware: clientAuth } = getClientAuth(provider);
  const PARAM_LIST = new Set(['token', 'token_type_hint', ...authParams]);
  const { grantTypeHandlers, configuration } = instance(provider);
  const {
    features: {
      revocation: { allowedPolicy },
    },
  } = configuration;

  function getAccessToken(token) {
    return provider.AccessToken.find(token);
  }

  function getClientCredentials(token) {
    if (!grantTypeHandlers.has('client_credentials')) {
      return undefined;
    }
    return provider.ClientCredentials.find(token);
  }

  function getRefreshToken(token) {
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
    ...clientAuth,
    rejectDupes.bind(undefined, {}),

    async function validateTokenPresence(ctx, next) {
      presence(ctx, 'token');
      await next();
    },

    rejectStructuredTokens,

    async function renderTokenResponse(ctx, next) {
      ctx.status = 200;
      ctx.body = '';
      await next();
    },

    async function revokeToken(ctx) {
      const { params } = ctx.oidc;

      let token;
      switch (params.token_type_hint) {
        case 'access_token':
        case 'urn:ietf:params:oauth:token-type:access_token':
          token = await Promise.all([
            getAccessToken(params.token),
            getClientCredentials(params.token),
          ])
            .then(findResult)
            .then((result) => result || getRefreshToken(params.token));
          break;
        case 'refresh_token':
        case 'urn:ietf:params:oauth:token-type:refresh_token':
          token = await getRefreshToken(params.token)
            .then((result) => result || Promise.all([
              getAccessToken(params.token),
              getClientCredentials(params.token),
            ]).then(findResult));
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

      if (
        token.kind === 'RefreshToken'
        && ctx.oidc.client.clientId === token.clientId
        && ctx.oidc.client.clientAuthMethod === 'attest_jwt_client_auth'
      ) {
        try {
          await checkAttestBinding(ctx, token);
        } catch {
          return;
        }
      }

      if (!(await allowedPolicy(ctx, ctx.oidc.client, token))) {
        return;
      }

      await token.destroy();

      if (token.kind === 'RefreshToken' || token.kind === 'AccessToken') {
        await revoke(ctx, token.grantId);
      }
    },
  ];
}
