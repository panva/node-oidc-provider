const difference = require('../../helpers/_/difference');
const { InvalidGrant, InvalidScope } = require('../../helpers/errors');
const presence = require('../../helpers/validate_presence');
const instance = require('../../helpers/weak_cache');
const revoke = require('../../helpers/revoke');
const { 'x5t#S256': thumbprint } = require('../../helpers/calculate_thumbprint');
const formatters = require('../../helpers/formatters');
const filterClaims = require('../../helpers/filter_claims');
const dpopValidate = require('../../helpers/validate_dpop');
const resolveResource = require('../../helpers/resolve_resource');

const gty = 'refresh_token';

module.exports.handler = async function refreshTokenHandler(ctx, next) {
  presence(ctx, 'refresh_token');

  const conf = instance(ctx.oidc.provider).configuration();

  const {
    conformIdTokenClaims,
    rotateRefreshToken,
    features: {
      userinfo,
      dPoP: { iatTolerance },
      mTLS: { getCertificate },
      resourceIndicators,
    },
  } = conf;

  const {
    RefreshToken, Account, AccessToken, IdToken, ReplayDetection,
  } = ctx.oidc.provider;
  const { client } = ctx.oidc;

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

  if (refreshToken['x5t#S256'] && refreshToken['x5t#S256'] !== thumbprint(cert)) {
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

  const dPoP = await dpopValidate(ctx);

  if (dPoP) {
    const unique = await ReplayDetection.unique(
      client.clientId, dPoP.jti, dPoP.iat + iatTolerance,
    );

    ctx.assert(unique, new InvalidGrant('DPoP Token Replay detected'));
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
    ctx, refreshToken, { userinfo, resourceIndicators }, scope,
  );

  if (resource) {
    const resourceServerInfo = await resourceIndicators
      .getResourceServerInfo(ctx, resource, ctx.oidc.client);
    at.resourceServer = new ctx.oidc.provider.ResourceServer(resource, resourceServerInfo);
    at.scope = grant.getResourceScopeFiltered(resource, scope);
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

module.exports.parameters = new Set(['refresh_token', 'scope']);
