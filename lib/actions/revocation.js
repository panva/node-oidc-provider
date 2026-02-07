import presence from '../helpers/validate_presence.js';
import instance from '../helpers/weak_cache.js';
import getClientAuth from '../shared/client_auth.js';
import { urlencoded as parseBody } from '../shared/selective_body.js';
import rejectDupes from '../shared/reject_dupes.js';
import paramsMiddleware from '../shared/assemble_params.js';
import rejectStructuredTokens from '../shared/reject_structured_tokens.js';
import revoke from '../helpers/revoke.js';
import { checkAttestBinding } from '../helpers/check_attest_binding.js';
import { createTokenFinder } from '../helpers/token_find.js';

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

  const findToken = createTokenFinder(provider, grantTypeHandlers);

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

      const token = await findToken(params.token, params.token_type_hint);

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
