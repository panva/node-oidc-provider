const uidToGrantId = require('debug')('oidc-provider:uid');

const get = require('../../helpers/_/get');
const difference = require('../../helpers/_/difference');
const { InvalidGrant, InvalidScope } = require('../../helpers/errors');
const presence = require('../../helpers/validate_presence');
const instance = require('../../helpers/weak_cache');
const revokeGrant = require('../../helpers/revoke_grant');
const { 'x5t#S256': thumbprint } = require('../../helpers/calculate_thumbprint');
const formatters = require('../../helpers/formatters');

const gty = 'refresh_token';

module.exports.handler = async function refreshTokenHandler(ctx, next) {
  presence(ctx, 'refresh_token');

  const conf = instance(ctx.oidc.provider).configuration();

  const {
    audiences,
    conformIdTokenClaims,
    rotateRefreshToken,
    features: { userinfo, dPoP: { iatTolerance }, mTLS: { getCertificate } },
  } = conf;

  const {
    RefreshToken, Account, AccessToken, IdToken, ReplayDetection,
  } = ctx.oidc.provider;

  let refreshTokenValue = ctx.oidc.params.refresh_token;
  let refreshToken = await RefreshToken.find(refreshTokenValue, { ignoreExpiration: true });

  if (!refreshToken) {
    throw new InvalidGrant('refresh token not found');
  }

  uidToGrantId('switched from uid=%s to value of grantId=%s', ctx.oidc.uid, refreshToken.grantId);
  ctx.oidc.uid = refreshToken.grantId;

  let cert;
  if (ctx.oidc.client.tlsClientCertificateBoundAccessTokens || refreshToken['x5t#S256']) {
    cert = getCertificate(ctx);
    if (!cert) {
      throw new InvalidGrant('mutual TLS client certificate not provided');
    }
  }

  if (refreshToken['x5t#S256'] && refreshToken['x5t#S256'] !== thumbprint(cert)) {
    throw new InvalidGrant('failed x5t#S256 verification');
  }

  if (refreshToken.isExpired) {
    throw new InvalidGrant('refresh token is expired');
  }

  if (refreshToken.clientId !== ctx.oidc.client.clientId) {
    throw new InvalidGrant('refresh token client mismatch');
  }

  if (ctx.oidc.params.scope) {
    const refreshTokenScopes = (refreshToken.scope || '').split(' ');
    const requested = ctx.oidc.params.scope.split(' ');
    const missing = difference(requested, refreshTokenScopes);

    if (missing.length !== 0) {
      throw new InvalidScope(`refresh token missing requested ${formatters.pluralize('scope', missing.length)}`, missing.join(' '));
    }
  }

  const { dPoP } = ctx.oidc;

  if (dPoP) {
    const unique = await ReplayDetection.unique(
      ctx.oidc.client.clientId, dPoP.jti, dPoP.iat + iatTolerance,
    );

    ctx.assert(unique, new InvalidGrant('DPoP Token Replay detected'));
  }

  if (refreshToken.jkt && (!dPoP || refreshToken.jkt !== dPoP.jwk.thumbprint)) {
    throw new InvalidGrant('failed jkt verification');
  }

  ctx.oidc.entity('RefreshToken', refreshToken);

  const account = await Account.findAccount(ctx, refreshToken.accountId, refreshToken);

  if (!account) {
    throw new InvalidGrant('refresh token invalid (referenced account not found)');
  }
  ctx.oidc.entity('Account', account);
  const scope = ctx.oidc.params.scope || refreshToken.scope;

  if (refreshToken.consumed) {
    await Promise.all([
      refreshToken.destroy(),
      revokeGrant(ctx.oidc.provider, ctx.oidc.client, refreshToken.grantId),
    ]);
    ctx.oidc.provider.emit('grant.revoked', ctx, refreshToken.grantId);
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
      client: ctx.oidc.client,
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
    claims: refreshToken.claims,
    client: ctx.oidc.client,
    expiresWithSession: refreshToken.expiresWithSession,
    grantId: refreshToken.grantId,
    gty: refreshToken.gty,
    scope,
    sessionUid: refreshToken.sessionUid,
    sid: refreshToken.sid,
  });

  if (ctx.oidc.client.tlsClientCertificateBoundAccessTokens) {
    at.setThumbprint('x5t', cert);
  }

  if (dPoP) {
    at.setThumbprint('jkt', dPoP.jwk);
  }

  if (at.gty && !at.gty.endsWith(gty)) {
    at.gty = `${at.gty} ${gty}`;
  }

  at.setAudiences(await audiences(ctx, account.accountId, at, 'access_token'));

  ctx.oidc.entity('AccessToken', at);
  const accessToken = await at.save();

  let idToken;
  if (at.scopes.has('openid')) {
    const claims = get(refreshToken, 'claims.id_token', {});
    const rejected = get(refreshToken, 'claims.rejected', []);
    const token = new IdToken(({
      ...await account.claims('id_token', scope, claims, rejected),
      acr: refreshToken.acr,
      amr: refreshToken.amr,
      auth_time: refreshToken.authTime,
    }), { ctx });

    if (conformIdTokenClaims && userinfo.enabled) {
      token.scope = 'openid';
    } else {
      token.scope = scope;
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
    scope,
    token_type: at.tokenType,
  };

  await next();
};

module.exports.parameters = new Set(['refresh_token', 'scope']);
