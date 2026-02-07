import {
  AuthorizationPending, ExpiredToken, InvalidGrant, InvalidRequest,
} from '../../helpers/errors.js';
import presence from '../../helpers/validate_presence.js';
import instance from '../../helpers/weak_cache.js';
import revoke from '../../helpers/revoke.js';
import dpopValidate from '../../helpers/validate_dpop.js';
import { checkAttestBinding } from '../../helpers/check_attest_binding.js';
import {
  throwIfAsyncGrantError,
  checkMtlsCert,
  checkDpopRequired,
  validateGrant,
  validateAccount,
  checkAccountMismatch,
  createAccessToken,
  applyMtlsBinding,
  applyDpopBinding,
  resolveAndApplyResource,
  createRefreshToken,
  issueIdToken,
  buildTokenResponse,
} from '../../helpers/grant_common.js';

export const gty = 'device_code';

export const handler = async function deviceCodeHandler(ctx) {
  presence(ctx, 'device_code');

  if (ctx.oidc.params.authorization_details) {
    throw new InvalidRequest('authorization_details is unsupported for this grant_type');
  }

  const {
    findAccount,
    issueRefreshToken,
    conformIdTokenClaims,
    features: {
      userinfo,
      mTLS: { getCertificate },
      dPoP: { allowReplay },
      resourceIndicators,
    },
  } = instance(ctx.oidc.provider).configuration;

  const dPoP = await dpopValidate(ctx);

  const code = await ctx.oidc.provider.DeviceCode.find(ctx.oidc.params.device_code, {
    ignoreExpiration: true,
  });

  if (!code) {
    throw new InvalidGrant('device code not found');
  }

  if (code.clientId !== ctx.oidc.client.clientId) {
    throw new InvalidGrant('client mismatch');
  }

  if (ctx.oidc.client.clientAuthMethod === 'attest_jwt_client_auth') {
    await checkAttestBinding(ctx, code);
  }

  const cert = checkMtlsCert(ctx, getCertificate);
  checkDpopRequired(ctx, dPoP);

  if (code.isExpired) {
    throw new ExpiredToken('device code is expired');
  }

  if (!code.accountId && !code.error) {
    throw new AuthorizationPending();
  }

  if (code.consumed) {
    await revoke(ctx, code.grantId);
    throw new InvalidGrant('device code already consumed');
  }

  await code.consume();

  throwIfAsyncGrantError(code);

  const grant = await validateGrant(ctx, code.grantId);

  ctx.oidc.entity('DeviceCode', code);
  ctx.oidc.entity('Grant', grant);

  const account = await validateAccount(ctx, findAccount, code, 'device code');
  checkAccountMismatch(code, grant);

  ctx.oidc.entity('Account', account);

  const { RefreshToken } = ctx.oidc.provider;

  const at = createAccessToken(
    ctx,
    ctx.oidc.provider.AccessToken,
    { ...code, accountId: account.accountId },
    gty,
  );
  applyMtlsBinding(at, cert);
  await applyDpopBinding(ctx, dPoP, at, allowReplay);

  await resolveAndApplyResource(ctx, code, at, grant, { userinfo, resourceIndicators });

  ctx.oidc.entity('AccessToken', at);
  const accessToken = await at.save();

  const refreshToken = await createRefreshToken(ctx, code, at, gty, {
    issueRefreshToken, RefreshToken,
  });

  const idToken = await issueIdToken(ctx, code, at, grant, {
    conformIdTokenClaims, userinfo,
  });

  ctx.body = buildTokenResponse(at, accessToken, {
    idToken, refreshToken, source: code,
  });
};

export const parameters = new Set(['device_code']);

export const grantType = 'urn:ietf:params:oauth:grant-type:device_code';
