import { AuthorizationPending, ExpiredToken } from '../../helpers/errors.js';
import presence from '../../helpers/validate_presence.js';
import instance from '../../helpers/weak_cache.js';
import dpopValidate from '../../helpers/validate_dpop.js';
import { checkAttestBinding } from '../../helpers/check_attest_binding.js';
import {
  throwIfAsyncGrantError,
  checkMtlsCert,
  checkDpopRequired,
  findGrantSource,
  consumeGrantSource,
  validateGrant,
  validateAccount,
  checkAccountMismatch,
  createAccessToken,
  applyMtlsBinding,
  applyDpopBinding,
  resolveAndApplyResource,
  applyAuthorizationDetails,
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
      resourceIndicators,
      richAuthorizationRequests,
    },
  } = instance(ctx.oidc.provider).configuration;

  const dPoP = await dpopValidate(ctx);

  const request = await findGrantSource(
    ctx,
    ctx.oidc.provider.BackchannelAuthenticationRequest,
    ctx.oidc.params.auth_req_id,
    'backchannel authentication request',
  );

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

  await consumeGrantSource(ctx, request, 'backchannel authentication request');

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
  await applyDpopBinding(ctx, dPoP, at);

  await resolveAndApplyResource(ctx, request, at, grant, { userinfo, resourceIndicators });
  await applyAuthorizationDetails(ctx, at, request, richAuthorizationRequests);

  ctx.oidc.entity('AccessToken', at);
  const accessToken = await at.save();

  const refreshToken = await createRefreshToken(ctx, request, at, gty, {
    issueRefreshToken, RefreshToken,
  });

  const idToken = await issueIdToken(ctx, request, at, grant, {
    conformIdTokenClaims, userinfo,
  });

  ctx.body = buildTokenResponse(at, accessToken, {
    idToken, refreshToken, source: request,
  });
};

export const parameters = new Set(['auth_req_id']);

export const grantType = 'urn:openid:params:grant-type:ciba';
