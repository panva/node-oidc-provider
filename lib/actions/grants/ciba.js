import { AuthorizationPending, ExpiredToken } from '../../helpers/errors.js';
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

export const gty = 'ciba';

export const handler = async function cibaHandler(provider, helpers, ctx) {
  const {
    findGrantSource,
    consumeGrantSource,
    validateGrant,
    resolveAndApplyResource,
    applyAuthorizationDetails,
    buildTokenResponse,
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

  const account = await validateAccount(provider, ctx, request, 'backchannel authentication request');
  checkAccountMismatch(request, grant);

  ctx.oidc.entity('Account', account);

  const at = createAccessToken(
    provider,
    ctx,
    { ...request, accountId: account.accountId },
    gty,
  );
  applyMtlsBinding(at, cert);
  await applyDpopBinding(provider, ctx, dPoP, at);

  await resolveAndApplyResource(ctx, request, at, grant);
  await applyAuthorizationDetails(ctx, at, request);

  ctx.oidc.entity('AccessToken', at);
  const accessToken = await at.save();

  const refreshToken = await createRefreshToken(provider, ctx, request, at, gty);

  const idToken = await issueIdToken(provider, ctx, request, at, grant);

  ctx.body = buildTokenResponse({
    accessToken,
    authorizationDetails: at.rar,
    expiresIn: at.expiration,
    idToken,
    refreshToken,
    scope: request.scope ? at.scope : (at.scope || undefined),
    tokenType: at.tokenType,
  });
};

export const parameters = new Set(['auth_req_id']);

export const grantType = 'urn:openid:params:grant-type:ciba';
