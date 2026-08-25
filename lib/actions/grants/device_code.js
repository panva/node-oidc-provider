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
  validateAccount,
  checkAccountMismatch,
  createAccessToken,
  applyMtlsBinding,
  applyDpopBinding,
  createRefreshToken,
  issueIdToken,
} from '../../helpers/grant_common.js';

export const gty = 'device_code';

export const handler = async function deviceCodeHandler(provider, helpers, ctx) {
  const {
    findGrantSource,
    consumeGrantSource,
    validateGrant,
    resolveAndApplyResource,
    applyAuthorizationDetails,
    buildTokenResponse,
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

  const account = await validateAccount(provider, ctx, code, 'device code');
  checkAccountMismatch(code, grant);

  ctx.oidc.entity('Account', account);

  const at = createAccessToken(
    provider,
    ctx,
    { ...code, accountId: account.accountId },
    gty,
  );
  applyMtlsBinding(at, cert);
  await applyDpopBinding(provider, ctx, dPoP, at);

  await resolveAndApplyResource(ctx, code, at, grant);
  await applyAuthorizationDetails(ctx, at, code);

  ctx.oidc.entity('AccessToken', at);
  const accessToken = await at.save();

  const refreshToken = await createRefreshToken(provider, ctx, code, at, gty);

  const idToken = await issueIdToken(provider, ctx, code, at, grant);

  ctx.body = buildTokenResponse({
    accessToken,
    authorizationDetails: at.rar,
    expiresIn: at.expiration,
    idToken,
    refreshToken,
    scope: code.scope ? at.scope : (at.scope || undefined),
    tokenType: at.tokenType,
  });
};

export const parameters = new Set(['device_code']);

export const grantType = 'urn:ietf:params:oauth:grant-type:device_code';
