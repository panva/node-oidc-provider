import difference from '../../helpers/_/difference.js';
import { InvalidRequest, InvalidGrant, InvalidScope } from '../../helpers/errors.js';
import presence from '../../helpers/validate_presence.js';
import instance from '../../helpers/weak_cache.js';
import revoke from '../../helpers/revoke.js';
import certificateThumbprint from '../../helpers/certificate_thumbprint.js';
import * as formatters from '../../helpers/formatters.js';
import dpopValidate, { CHALLENGE_OK_WINDOW } from '../../helpers/validate_dpop.js';
import resolveResource from '../../helpers/resolve_resource.js';
import epochTime from '../../helpers/epoch_time.js';
import checkRar from '../../shared/check_rar.js';
import { checkAttestBinding } from '../../helpers/check_attest_binding.js';
import {
  checkDpopRequired,
  validateGrant,
  validateAccount,
  checkAccountMismatch,
  createAccessToken,
  applyMtlsBinding,
  issueIdToken,
  buildTokenResponse,
} from '../../helpers/grant_common.js';

import { gty as deviceCodeGty } from './device_code.js';

function rarSupported(token) {
  const [origin] = token.gty.split(' ');
  return origin !== deviceCodeGty;
}

const gty = 'refresh_token';

export const handler = async function refreshTokenHandler(ctx) {
  presence(ctx, 'refresh_token');

  const {
    findAccount,
    conformIdTokenClaims,
    rotateRefreshToken,
    features: {
      userinfo,
      mTLS: { getCertificate },
      dPoP: { allowReplay },
      resourceIndicators,
      richAuthorizationRequests,
    },
  } = instance(ctx.oidc.provider).configuration;

  const {
    RefreshToken, AccessToken, ReplayDetection,
  } = ctx.oidc.provider;
  const { client } = ctx.oidc;

  const dPoP = await dpopValidate(ctx);

  let refreshTokenValue = ctx.oidc.params.refresh_token;
  let refreshToken = await RefreshToken.find(refreshTokenValue, { ignoreExpiration: true });

  if (!refreshToken) {
    throw new InvalidGrant('refresh token not found');
  }

  if (refreshToken.clientId !== client.clientId) {
    throw new InvalidGrant('client mismatch');
  }

  if (refreshToken.isExpired) {
    throw new InvalidGrant('refresh token is expired');
  }

  let cert;
  if (client.tlsClientCertificateBoundAccessTokens || refreshToken['x5t#S256']) {
    cert = getCertificate(ctx);
    if (!cert) {
      throw new InvalidGrant('mutual TLS client certificate not provided');
    }
  }

  checkDpopRequired(ctx, dPoP);

  if (refreshToken['x5t#S256'] && refreshToken['x5t#S256'] !== certificateThumbprint(cert)) {
    throw new InvalidGrant('failed x5t#S256 verification');
  }

  const grant = await validateGrant(ctx, refreshToken.grantId);

  if (ctx.oidc.params.scope) {
    const missing = difference([...ctx.oidc.requestParamScopes], [...refreshToken.scopes]);

    if (missing.length !== 0) {
      throw new InvalidScope(`refresh token missing requested ${formatters.pluralize('scope', missing.length)}`, missing.join(' '));
    }
  }

  if (dPoP && !allowReplay) {
    const unique = await ReplayDetection.unique(
      client.clientId,
      dPoP.jti,
      epochTime() + CHALLENGE_OK_WINDOW,
    );

    ctx.assert(unique, new InvalidGrant('DPoP proof JWT Replay detected'));
  }

  if (refreshToken.jkt && (!dPoP || refreshToken.jkt !== dPoP.thumbprint)) {
    throw new InvalidGrant('failed jkt verification');
  }

  if (ctx.oidc.client.clientAuthMethod === 'attest_jwt_client_auth') {
    await checkAttestBinding(ctx, refreshToken);
  }

  ctx.oidc.entity('RefreshToken', refreshToken);
  ctx.oidc.entity('Grant', grant);

  const account = await validateAccount(ctx, findAccount, refreshToken, 'refresh token');
  checkAccountMismatch(refreshToken, grant);

  ctx.oidc.entity('Account', account);

  if (refreshToken.consumed) {
    await Promise.all([
      refreshToken.destroy(),
      revoke(ctx, refreshToken.grantId),
    ]);
    throw new InvalidGrant('refresh token already used');
  }

  if (ctx.oidc.params.authorization_details && !rarSupported(refreshToken)) {
    throw new InvalidRequest('authorization_details is unsupported for this refresh token');
  }

  if (
    rotateRefreshToken === true
    || (typeof rotateRefreshToken === 'function' && await rotateRefreshToken(ctx))
  ) {
    await refreshToken.consume();
    ctx.oidc.entity('RotatedRefreshToken', refreshToken);

    refreshToken = new RefreshToken({
      accountId: refreshToken.accountId,
      acr: refreshToken.acr,
      amr: refreshToken.amr,
      authTime: refreshToken.authTime,
      claims: refreshToken.claims,
      client,
      expiresWithSession: refreshToken.expiresWithSession,
      iiat: refreshToken.iiat,
      grantId: refreshToken.grantId,
      gty: refreshToken.gty,
      nonce: refreshToken.nonce,
      resource: refreshToken.resource,
      rotations: typeof refreshToken.rotations === 'number' ? refreshToken.rotations + 1 : 1,
      scope: refreshToken.scope,
      sessionUid: refreshToken.sessionUid,
      sid: refreshToken.sid,
      rar: refreshToken.rar,
      'x5t#S256': refreshToken['x5t#S256'],
      jkt: refreshToken.jkt,
      attestationJkt: refreshToken.attestationJkt,
    });

    if (refreshToken.gty && !refreshToken.gty.endsWith(gty)) {
      refreshToken.gty = `${refreshToken.gty} ${gty}`;
    }

    ctx.oidc.entity('RefreshToken', refreshToken);
    refreshTokenValue = await refreshToken.save();
  }

  const at = createAccessToken(ctx, AccessToken, {
    accountId: account.accountId,
    expiresWithSession: refreshToken.expiresWithSession,
    grantId: refreshToken.grantId,
    sessionUid: refreshToken.sessionUid,
    sid: refreshToken.sid,
  }, refreshToken.gty);

  applyMtlsBinding(at, cert);

  if (dPoP) {
    at.setThumbprint('jkt', dPoP.thumbprint);
  }

  if (at.gty && !at.gty.endsWith(gty)) {
    at.gty = `${at.gty} ${gty}`;
  }

  const scope = ctx.oidc.params.scope ? ctx.oidc.requestParamScopes : refreshToken.scopes;
  await checkRar(ctx, () => {});
  const resource = await resolveResource(
    ctx,
    refreshToken,
    { userinfo, resourceIndicators },
    scope,
  );

  if (resource) {
    const resourceServerInfo = await resourceIndicators
      .getResourceServerInfo(ctx, resource, ctx.oidc.client);
    at.resourceServer = new ctx.oidc.provider.ResourceServer(resource, resourceServerInfo);
    at.scope = grant.getResourceScopeFiltered(
      resource,
      [...scope].filter(Set.prototype.has.bind(at.resourceServer.scopes)),
    );
  } else {
    at.claims = refreshToken.claims;
    at.scope = grant.getOIDCScopeFiltered(scope);
  }

  if (richAuthorizationRequests.enabled && at.resourceServer) {
    at.rar = await richAuthorizationRequests.rarForRefreshTokenResponse(ctx, at.resourceServer);
  }

  ctx.oidc.entity('AccessToken', at);
  const accessToken = await at.save();

  const idToken = await issueIdToken(ctx, refreshToken, at, grant, {
    conformIdTokenClaims, userinfo,
  }, scope);

  ctx.body = buildTokenResponse(at, accessToken, {
    idToken, refreshToken: refreshTokenValue, source: refreshToken, rar: at.rar,
  });
};

export const parameters = new Set(['refresh_token', 'scope']);

export const grantType = gty;
