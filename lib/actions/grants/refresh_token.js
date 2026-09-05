import difference from '../../helpers/_/difference.js';
import certificateThumbprint from '../../helpers/certificate_thumbprint.js';
import { checkAttestBinding } from '../../helpers/check_attest_binding.js';
import {
  boolean,
  resourceServer as validateResourceServer,
} from '../../helpers/configuration_result.js';
import { InvalidGrant, InvalidScope } from '../../helpers/errors.js';
import * as formatters from '../../helpers/formatters.js';
import {
  applyMtlsBinding,
  checkAccountMismatch,
  createAccessToken,
  issueIdToken,
  validateAccount,
} from '../../helpers/grant_common.js';
import resolveResource from '../../helpers/resolve_resource.js';
import revoke from '../../helpers/revoke.js';
import presence from '../../helpers/validate_presence.js';
import instance from '../../helpers/weak_cache.js';

const gty = 'refresh_token';

export const handler = async function refreshTokenHandler(provider, helpers, ctx) {
  const {
    checkDpopReplay,
    checkDpopRequired,
    validateDpop,
    validateGrant,
    applyAuthorizationDetails,
    buildTokenResponse,
  } = helpers;

  presence(ctx, 'refresh_token');

  const {
    rotateRefreshToken,
    features: {
      userinfo,
      mTLS: { getCertificate },
      resourceIndicators,
    },
  } = instance(provider).configuration;

  const { RefreshToken } = provider;
  const { client } = ctx.oidc;

  const dPoP = await validateDpop(ctx);

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

  await checkDpopReplay(ctx, dPoP, client.clientId, InvalidGrant);

  if (refreshToken.jkt && (!dPoP || refreshToken.jkt !== dPoP.thumbprint)) {
    throw new InvalidGrant('failed jkt verification');
  }

  if (ctx.oidc.client.clientAuthMethod === 'attest_jwt_client_auth') {
    await checkAttestBinding(ctx, refreshToken);
  }

  ctx.oidc.entity('RefreshToken', refreshToken);
  ctx.oidc.entity('Grant', grant);

  const account = await validateAccount(provider, ctx, refreshToken, 'refresh token');
  checkAccountMismatch(refreshToken, grant);

  ctx.oidc.entity('Account', account);

  if (refreshToken.consumed) {
    await Promise.all([
      refreshToken.destroy(),
      revoke(ctx, refreshToken.grantId),
    ]);
    throw new InvalidGrant('refresh token already used');
  }

  if (
    rotateRefreshToken === true
    || (
      typeof rotateRefreshToken === 'function'
      && boolean(await rotateRefreshToken(ctx), 'rotateRefreshToken')
    )
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

  const at = createAccessToken(provider, ctx, {
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
  const resource = await resolveResource(
    ctx,
    refreshToken,
    { userinfo, resourceIndicators },
    scope,
  );

  if (resource) {
    const resourceServerInfo = validateResourceServer(
      await resourceIndicators.getResourceServerInfo(ctx, resource, ctx.oidc.client),
    );
    at.resourceServer = new provider.ResourceServer(resource, resourceServerInfo);
    at.scope = grant.getResourceScopeFiltered(
      resource,
      [...scope].filter(Set.prototype.has.bind(at.resourceServer.scopes)),
    );
  } else {
    at.claims = refreshToken.claims;
    at.scope = grant.getOIDCScopeFiltered(scope);
  }

  await applyAuthorizationDetails(ctx, at, refreshToken);

  ctx.oidc.entity('AccessToken', at);
  const accessToken = await at.save();

  const idToken = await issueIdToken(provider, ctx, refreshToken, at, grant, scope);

  ctx.body = buildTokenResponse({
    accessToken,
    authorizationDetails: at.rar,
    expiresIn: at.expiration,
    idToken,
    refreshToken: refreshTokenValue,
    scope: refreshToken.scope ? at.scope : (at.scope || undefined),
    tokenType: at.tokenType,
  });
};

export const parameters = new Set(['refresh_token', 'scope']);

export const grantType = gty;
