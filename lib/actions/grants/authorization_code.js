import { InvalidGrant } from '../../helpers/errors.js';
import presence from '../../helpers/validate_presence.js';
import instance from '../../helpers/weak_cache.js';
import checkPKCE from '../../helpers/pkce.js';
import revoke from '../../helpers/revoke.js';
import dpopValidate from '../../helpers/validate_dpop.js';
import checkRar from '../../shared/check_rar.js';
import { checkAttestBinding } from '../../helpers/check_attest_binding.js';
import {
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

const gty = 'authorization_code';

export const handler = async function authorizationCodeHandler(ctx) {
  const {
    findAccount,
    issueRefreshToken,
    allowOmittingSingleRegisteredRedirectUri,
    conformIdTokenClaims,
    features: {
      userinfo,
      mTLS: { getCertificate },
      resourceIndicators,
      richAuthorizationRequests,
      dPoP: { allowReplay },
    },
  } = instance(ctx.oidc.provider).configuration;

  if (allowOmittingSingleRegisteredRedirectUri && ctx.oidc.params.redirect_uri === undefined) {
    // It is permitted to omit the redirect_uri if only ONE is registered on the client
    const { 0: uri, length } = ctx.oidc.client.redirectUris;
    if (uri && length === 1) {
      ctx.oidc.params.redirect_uri = uri;
    }
  }

  presence(ctx, 'code', 'redirect_uri');

  const dPoP = await dpopValidate(ctx);

  const code = await ctx.oidc.provider.AuthorizationCode.find(ctx.oidc.params.code, {
    ignoreExpiration: true,
  });

  if (!code) {
    throw new InvalidGrant('authorization code not found');
  }

  if (code.clientId !== ctx.oidc.client.clientId) {
    throw new InvalidGrant('client mismatch');
  }

  if (code.isExpired) {
    throw new InvalidGrant('authorization code is expired');
  }

  const grant = await validateGrant(ctx, code.grantId);

  checkPKCE(ctx.oidc.params.code_verifier, code.codeChallenge, code.codeChallengeMethod);

  const cert = checkMtlsCert(ctx, getCertificate);
  checkDpopRequired(ctx, dPoP);

  if (code.redirectUri !== ctx.oidc.params.redirect_uri) {
    throw new InvalidGrant('authorization code redirect_uri mismatch');
  }

  if (ctx.oidc.client.clientAuthMethod === 'attest_jwt_client_auth' && code.attestationJkt) {
    await checkAttestBinding(ctx, code);
  }

  if (code.consumed) {
    await revoke(ctx, code.grantId);
    throw new InvalidGrant('authorization code already consumed');
  }

  await code.consume();

  ctx.oidc.entity('AuthorizationCode', code);
  ctx.oidc.entity('Grant', grant);

  const account = await validateAccount(ctx, findAccount, code, 'authorization code');
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

  if (code.dpopJkt && !dPoP) {
    throw new InvalidGrant('missing DPoP proof JWT');
  }

  await applyDpopBinding(ctx, dPoP, at, allowReplay);

  if (dPoP && code.dpopJkt && code.dpopJkt !== dPoP.thumbprint) {
    throw new InvalidGrant('DPoP proof key thumbprint does not match dpop_jkt');
  }

  await checkRar(ctx, () => {});
  await resolveAndApplyResource(ctx, code, at, grant, { userinfo, resourceIndicators });

  if (richAuthorizationRequests.enabled && at.resourceServer) {
    at.rar = await richAuthorizationRequests.rarForCodeResponse(ctx, at.resourceServer);
  }

  ctx.oidc.entity('AccessToken', at);
  const accessToken = await at.save();

  const refreshToken = await createRefreshToken(ctx, code, at, gty, {
    issueRefreshToken, RefreshToken,
  });

  const idToken = await issueIdToken(ctx, code, at, grant, {
    conformIdTokenClaims, userinfo,
  });

  ctx.body = buildTokenResponse(at, accessToken, {
    idToken, refreshToken, source: code, rar: at.rar,
  });
};

export const parameters = new Set(['code', 'code_verifier', 'redirect_uri']);

export const grantType = gty;
