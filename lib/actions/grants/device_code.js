import {
  AuthorizationPending, ExpiredToken,
} from '../../helpers/errors.js';
import presence from '../../helpers/validate_presence.js';
import dpopValidate from '../../helpers/validate_dpop.js';
import { checkAttestBinding } from '../../helpers/check_attest_binding.js';
import {
  throwIfAsyncGrantError,
  checkMtlsCert,
  checkDpopRequired,
  issueTokens,
} from '../../helpers/grant_common.js';

export const gty = 'device_code';

export const handler = async function deviceCodeHandler(provider, helpers, ctx) {
  const {
    findGrantSource,
    consumeGrantSource,
    validateGrant,
  } = helpers;

  presence(ctx, 'device_code');

  const dPoP = await dpopValidate(ctx);

  const code = await findGrantSource(
    ctx,
    provider.DeviceCode,
    ctx.oidc.params.device_code,
    'device code',
  );

  if (ctx.oidc.client.clientAuthMethod === 'attest_jwt_client_auth') {
    await checkAttestBinding(ctx, code);
  }

  const cert = checkMtlsCert(provider, ctx);
  checkDpopRequired(provider, ctx, dPoP);

  if (code.isExpired) {
    throw new ExpiredToken('device code is expired');
  }

  if (!code.accountId && !code.error) {
    throw new AuthorizationPending();
  }

  await consumeGrantSource(ctx, code, 'device code');

  throwIfAsyncGrantError(code);

  const grant = await validateGrant(ctx, code.grantId);

  ctx.oidc.entity('DeviceCode', code);
  ctx.oidc.entity('Grant', grant);

  await issueTokens(provider, helpers, ctx, code, grant, {
    gty, entityLabel: 'device code', cert, dPoP,
  });
};

export const parameters = new Set(['device_code']);

export const grantType = 'urn:ietf:params:oauth:grant-type:device_code';
