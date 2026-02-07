import { AuthorizationPending, ExpiredToken, InvalidGrant } from '../../helpers/errors.js';
import presence from '../../helpers/validate_presence.js';
import instance from '../../helpers/weak_cache.js';
import revoke from '../../helpers/revoke.js';
import dpopValidate from '../../helpers/validate_dpop.js';
import { checkAttestBinding } from '../../helpers/check_attest_binding.js';
import checkRar from '../../shared/check_rar.js';
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

export const gty = 'ciba';

export const handler = async function cibaHandler(ctx) {
  presence(ctx, 'auth_req_id');

  const {
    findAccount,
    issueRefreshToken,
    conformIdTokenClaims,
    features: {
      userinfo,
      mTLS: { getCertificate },
      dPoP: { allowReplay },
      resourceIndicators,
      richAuthorizationRequests,
    },
  } = instance(ctx.oidc.provider).configuration;

  const dPoP = await dpopValidate(ctx);

  const request = await ctx.oidc.provider.BackchannelAuthenticationRequest.find(
    ctx.oidc.params.auth_req_id,
    { ignoreExpiration: true },
  );

  if (!request) {
    throw new InvalidGrant('backchannel authentication request not found');
  }

  if (request.clientId !== ctx.oidc.client.clientId) {
    throw new InvalidGrant('client mismatch');
  }

  const cert = checkMtlsCert(ctx, getCertificate);
  checkDpopRequired(ctx, dPoP);

  if (request.isExpired) {
    throw new ExpiredToken('backchannel authentication request is expired');
  }

  if (!request.grantId && !request.error) {
    throw new AuthorizationPending();
  }

  if (ctx.oidc.client.clientAuthMethod === 'attest_jwt_client_auth') {
    await checkAttestBinding(ctx, request);
  }

  if (request.consumed) {
    await revoke(ctx, request.grantId);
    throw new InvalidGrant('backchannel authentication request already consumed');
  }

  await request.consume();

  throwIfAsyncGrantError(request);

  const grant = await validateGrant(ctx, request.grantId);

  ctx.oidc.entity('BackchannelAuthenticationRequest', request);
  ctx.oidc.entity('Grant', grant);

  const account = await validateAccount(ctx, findAccount, request, 'backchannel authentication request');
  checkAccountMismatch(request, grant);

  ctx.oidc.entity('Account', account);

  const { RefreshToken } = ctx.oidc.provider;

  const at = createAccessToken(
    ctx,
    ctx.oidc.provider.AccessToken,
    { ...request, accountId: account.accountId },
    gty,
  );
  applyMtlsBinding(at, cert);
  await applyDpopBinding(ctx, dPoP, at, allowReplay);

  await checkRar(ctx, () => {});
  await resolveAndApplyResource(ctx, request, at, grant, { userinfo, resourceIndicators });

  if (richAuthorizationRequests.enabled && at.resourceServer) {
    at.rar = await richAuthorizationRequests.rarForBackchannelResponse(ctx, at.resourceServer);
  }

  ctx.oidc.entity('AccessToken', at);
  const accessToken = await at.save();

  const refreshToken = await createRefreshToken(ctx, request, at, gty, {
    issueRefreshToken, RefreshToken,
  });

  const idToken = await issueIdToken(ctx, request, at, grant, {
    conformIdTokenClaims, userinfo,
  });

  ctx.body = buildTokenResponse(at, accessToken, {
    idToken, refreshToken, source: request, rar: at.rar,
  });
};

export const parameters = new Set(['auth_req_id']);

export const grantType = 'urn:openid:params:grant-type:ciba';
