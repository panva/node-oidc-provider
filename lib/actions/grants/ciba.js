import { AuthorizationPending, ExpiredToken } from '../../helpers/errors.js';
import presence from '../../helpers/validate_presence.js';
import dpopValidate from '../../helpers/validate_dpop.js';
import { checkAttestBinding } from '../../helpers/check_attest_binding.js';
import {
  throwIfAsyncGrantError,
  checkMtlsCert,
  checkDpopRequired,
  issueTokens,
} from '../../helpers/grant_common.js';

export const gty = 'ciba';

export const handler = async function cibaHandler(provider, helpers, ctx) {
  const {
    findGrantSource,
    consumeGrantSource,
    validateGrant,
  } = helpers;

  presence(ctx, 'auth_req_id');

  const dPoP = await dpopValidate(ctx);

  const request = await findGrantSource(
    ctx,
    provider.BackchannelAuthenticationRequest,
    ctx.oidc.params.auth_req_id,
    'backchannel authentication request',
  );

  const cert = checkMtlsCert(provider, ctx);
  checkDpopRequired(provider, ctx, dPoP);

  if (request.isExpired) {
    throw new ExpiredToken('backchannel authentication request is expired');
  }

  if (!request.grantId && !request.error) {
    throw new AuthorizationPending();
  }

  if (ctx.oidc.client.clientAuthMethod === 'attest_jwt_client_auth') {
    await checkAttestBinding(ctx, request);
  }

  await consumeGrantSource(ctx, request, 'backchannel authentication request');

  throwIfAsyncGrantError(request);

  const grant = await validateGrant(ctx, request.grantId);

  ctx.oidc.entity('BackchannelAuthenticationRequest', request);
  ctx.oidc.entity('Grant', grant);

  await issueTokens(provider, helpers, ctx, request, grant, {
    gty, entityLabel: 'backchannel authentication request', cert, dPoP,
  });
};

export const parameters = new Set(['auth_req_id']);

export const grantType = 'urn:openid:params:grant-type:ciba';
