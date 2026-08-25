import { InvalidGrant } from '../../helpers/errors.js';
import presence from '../../helpers/validate_presence.js';
import instance from '../../helpers/weak_cache.js';
import checkPKCE from '../../helpers/pkce.js';
import dpopValidate from '../../helpers/validate_dpop.js';
import { checkAttestBinding } from '../../helpers/check_attest_binding.js';
import {
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

const gty = 'authorization_code';

export const handler = async function authorizationCodeHandler(provider, helpers, ctx) {
  const {
    findGrantSource,
    consumeGrantSource,
    validateGrant,
    resolveAndApplyResource,
    applyAuthorizationDetails,
    buildTokenResponse,
  } = helpers;

  const {
    allowOmittingSingleRegisteredRedirectUri,
  } = instance(provider).configuration;

  if (allowOmittingSingleRegisteredRedirectUri && ctx.oidc.params.redirect_uri === undefined) {
    // It is permitted to omit the redirect_uri if only ONE is registered on the client
    const { 0: uri, length } = ctx.oidc.client.redirectUris;
    if (uri && length === 1) {
      ctx.oidc.params.redirect_uri = uri;
    }
  }

  presence(ctx, 'code', 'redirect_uri');

  const dPoP = await dpopValidate(ctx);

  const code = await findGrantSource(
    ctx,
    provider.AuthorizationCode,
    ctx.oidc.params.code,
    'authorization code',
  );

  if (code.isExpired) {
    throw new InvalidGrant('authorization code is expired');
  }

  const grant = await validateGrant(ctx, code.grantId);

  checkPKCE(ctx.oidc.params.code_verifier, code.codeChallenge, code.codeChallengeMethod);

  const cert = checkMtlsCert(provider, ctx);
  checkDpopRequired(provider, ctx, dPoP);

  if (code.redirectUri !== ctx.oidc.params.redirect_uri) {
    throw new InvalidGrant('authorization code redirect_uri mismatch');
  }

  if (ctx.oidc.client.clientAuthMethod === 'attest_jwt_client_auth' && code.attestationJkt) {
    await checkAttestBinding(ctx, code);
  }

  await consumeGrantSource(ctx, code, 'authorization code');

  ctx.oidc.entity('AuthorizationCode', code);
  ctx.oidc.entity('Grant', grant);

  const account = await validateAccount(provider, ctx, code, 'authorization code');
  checkAccountMismatch(code, grant);

  ctx.oidc.entity('Account', account);

  const at = createAccessToken(
    provider,
    ctx,
    { ...code, accountId: account.accountId },
    gty,
  );
  applyMtlsBinding(at, cert);

  if (code.dpopJkt && !dPoP) {
    throw new InvalidGrant('missing DPoP proof JWT');
  }

  await applyDpopBinding(provider, ctx, dPoP, at);

  if (dPoP && code.dpopJkt && code.dpopJkt !== dPoP.thumbprint) {
    throw new InvalidGrant('DPoP proof key thumbprint does not match dpop_jkt');
  }

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

export const parameters = new Set(['code', 'code_verifier', 'redirect_uri']);

export const grantType = gty;
