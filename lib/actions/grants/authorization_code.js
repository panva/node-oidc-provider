import { InvalidGrant } from '../../helpers/errors.js';
import presence from '../../helpers/validate_presence.js';
import instance from '../../helpers/weak_cache.js';
import checkPKCE from '../../helpers/pkce.js';
import { checkAttestBinding } from '../../helpers/check_attest_binding.js';
import { issueTokens } from '../../helpers/grant_common.js';

const gty = 'authorization_code';

export const handler = async function authorizationCodeHandler(provider, helpers, ctx) {
  const {
    checkDpopRequired,
    checkMtlsCert,
    validateDpop,
    findGrantSource,
    consumeGrantSource,
    validateGrant,
  } = helpers;

  const {
    allowOmittingSingleRegisteredRedirectUri,
  } = instance(provider).configuration;

  presence(ctx, 'code');

  const dPoP = await validateDpop(ctx);

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

  if (!code.codeChallenge || code.codeChallengeMethod !== 'S256') {
    if (allowOmittingSingleRegisteredRedirectUri && ctx.oidc.params.redirect_uri === undefined) {
      // Without PKCE, only the existing single registered URI exception applies.
      const { 0: uri, length } = ctx.oidc.client.redirectUris;
      if (uri && length === 1) {
        ctx.oidc.params.redirect_uri = uri;
      }
    }

    presence(ctx, 'redirect_uri');
  }

  const cert = checkMtlsCert(ctx);
  checkDpopRequired(ctx, dPoP);

  if (
    ctx.oidc.params.redirect_uri !== undefined
    && code.redirectUri !== ctx.oidc.params.redirect_uri
  ) {
    throw new InvalidGrant('authorization code redirect_uri mismatch');
  }

  if (['attest_jwt_client_auth', 'attest_jwt_client_auth_dpop'].includes(ctx.oidc.client.clientAuthMethod) && code.attestationJkt) {
    await checkAttestBinding(ctx, code);
  }

  await consumeGrantSource(ctx, code, 'authorization code');

  ctx.oidc.entity('AuthorizationCode', code);
  ctx.oidc.entity('Grant', grant);

  await issueTokens(provider, helpers, ctx, code, grant, {
    gty, entityLabel: 'authorization code', cert, dPoP,
  });
};

export const parameters = new Set(['code', 'code_verifier', 'redirect_uri']);

export const grantType = gty;
