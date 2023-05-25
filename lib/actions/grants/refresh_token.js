import difference from '../../helpers/_/difference.js';
import { InvalidGrant, InvalidScope } from '../../helpers/errors.js';
import presence from '../../helpers/validate_presence.js';
import instance from '../../helpers/weak_cache.js';
import revoke from '../../helpers/revoke.js';
import certificateThumbprint from '../../helpers/certificate_thumbprint.js';
import * as formatters from '../../helpers/formatters.js';
import filterClaims from '../../helpers/filter_claims.js';
import dpopValidate from '../../helpers/validate_dpop.js';
import resolveResource from '../../helpers/resolve_resource.js';
import epochTime from '../../helpers/epoch_time.js';

const gty = 'refresh_token';

export const handler = async function refreshTokenHandler(ctx, next) {
  presence(ctx, 'refresh_token');

  const conf = instance(ctx.oidc.provider).configuration();

  const {
    conformIdTokenClaims,
    rotateRefreshToken,
    features: {
      userinfo,
      mTLS: { getCertificate },
      resourceIndicators,
    },
  } = conf;

  const {
    RefreshToken, Account, AccessToken, IdToken, ReplayDetection,
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

  if (!dPoP && ctx.oidc.client.dpopBoundAccessTokens) {
    throw new InvalidGrant('DPoP proof JWT not provided');
  }

  if (refreshToken['x5t#S256'] && refreshToken['x5t#S256'] !== certificateThumbprint(cert)) {
    throw new InvalidGrant('failed x5t#S256 verification');
  }

  const grant = await ctx.oidc.provider.Grant.find(refreshToken.grantId, {
    ignoreExpiration: true,
  });

  if (!grant) {
    throw new InvalidGrant('grant not found');
  }

  if (grant.isExpired) {
    throw new InvalidGrant('grant is expired');
  }

  if (grant.clientId !== client.clientId) {
    throw new InvalidGrant('client mismatch');
  }

  if (ctx.oidc.params.scope) {
    const missing = difference([...ctx.oidc.requestParamScopes], [...refreshToken.scopes]);

    if (missing.length !== 0) {
      throw new InvalidScope(`refresh token missing requested ${formatters.pluralize('scope', missing.length)}`, missing.join(' '));
    }
  }

  if (dPoP) {
    const unique = await ReplayDetection.unique(client.clientId, dPoP.jti, epochTime() + 300);

    ctx.assert(unique, new InvalidGrant('DPoP proof JWT Replay detected'));
  }

  if (refreshToken.jkt && (!dPoP || refreshToken.jkt !== dPoP.thumbprint)) {
    throw new InvalidGrant('failed jkt verification');
  }

  ctx.oidc.entity('RefreshToken', refreshToken);
  ctx.oidc.entity('Grant', grant);

  const account = await Account.findAccount(ctx, refreshToken.accountId, refreshToken);

  if (!account) {
    throw new InvalidGrant('refresh token invalid (referenced account not found)');
  }

  if (refreshToken.accountId !== grant.accountId) {
    throw new InvalidGrant('accountId mismatch');
  }

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
      'x5t#S256': refreshToken['x5t#S256'],
      jkt: refreshToken.jkt,
    });

    if (refreshToken.gty && !refreshToken.gty.endsWith(gty)) {
      refreshToken.gty = `${refreshToken.gty} ${gty}`;
    }

    ctx.oidc.entity('RefreshToken', refreshToken);
    refreshTokenValue = await refreshToken.save();
  }

  const at = new AccessToken({
    accountId: account.accountId,
    client,
    expiresWithSession: refreshToken.expiresWithSession,
    grantId: refreshToken.grantId,
    gty: refreshToken.gty,
    sessionUid: refreshToken.sessionUid,
    sid: refreshToken.sid,
  });

  if (client.tlsClientCertificateBoundAccessTokens) {
    at.setThumbprint('x5t', cert);
  }

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

  ctx.oidc.entity('AccessToken', at);
  const accessToken = await at.save();

  let idToken;
  if (scope.has('openid')) {
    const claims = filterClaims(refreshToken.claims, 'id_token', grant);
    const rejected = grant.getRejectedOIDCClaims();
    const token = new IdToken(({
      ...await account.claims('id_token', [...scope].join(' '), claims, rejected),
      acr: refreshToken.acr,
      amr: refreshToken.amr,
      auth_time: refreshToken.authTime,
    }), { ctx });

    if (conformIdTokenClaims && userinfo.enabled && !at.aud) {
      token.scope = 'openid';
    } else {
      token.scope = grant.getOIDCScopeFiltered(scope);
    }
    token.mask = claims;
    token.rejected = rejected;

    token.set('nonce', refreshToken.nonce);
    token.set('at_hash', accessToken);
    token.set('sid', refreshToken.sid);

    idToken = await token.issue({ use: 'idtoken' });
  }

  ctx.body = {
    access_token: accessToken,
    expires_in: at.expiration,
    id_token: idToken,
    refresh_token: refreshTokenValue,
    scope: at.scope,
    token_type: at.tokenType,
  };

  await next();
};

export const parameters = new Set(['refresh_token', 'scope']);
