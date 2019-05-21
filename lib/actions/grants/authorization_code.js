const { get } = require('lodash');
const uidToGrantId = require('debug')('oidc-provider:uid');

const { InvalidGrant } = require('../../helpers/errors');
const presence = require('../../helpers/validate_presence');
const instance = require('../../helpers/weak_cache');
const checkPKCE = require('../../helpers/pkce');
const revokeGrant = require('../../helpers/revoke_grant');

const gty = 'authorization_code';

module.exports.handler = async function authorizationCodeHandler(ctx, next) {
  const {
    issueRefreshToken,
    audiences,
    conformIdTokenClaims,
  } = instance(ctx.oidc.provider).configuration();

  if (ctx.oidc.params.redirect_uri === undefined) {
    // It is permitted to omit the redirect_uri if only ONE is registered on the client
    const { 0: uri, length } = ctx.oidc.client.redirectUris;
    if (uri && length === 1) {
      ctx.oidc.params.redirect_uri = uri;
    }
  }

  presence(ctx, 'code', 'redirect_uri');

  const code = await ctx.oidc.provider.AuthorizationCode.find(ctx.oidc.params.code, {
    ignoreExpiration: true,
  });

  if (!code) {
    throw new InvalidGrant('authorization code not found');
  }

  uidToGrantId('switched from uid=%s to value of grantId=%s', ctx.oidc.uid, code.grantId);
  ctx.oidc.uid = code.grantId;

  if (code.isExpired) {
    throw new InvalidGrant('authorization code is expired');
  }

  checkPKCE(ctx.oidc.params.code_verifier, code.codeChallenge, code.codeChallengeMethod);

  if (code.clientId !== ctx.oidc.client.clientId) {
    throw new InvalidGrant('authorization code client mismatch');
  }

  if (code.consumed) {
    await Promise.all([
      code.destroy(),
      revokeGrant(ctx.oidc.provider, ctx.oidc.client, code.grantId),
    ]);
    ctx.oidc.provider.emit('grant.revoked', ctx, code.grantId);
    throw new InvalidGrant('authorization code already consumed');
  }

  await code.consume();

  if (code.redirectUri !== ctx.oidc.params.redirect_uri) {
    throw new InvalidGrant('authorization code redirect_uri mismatch');
  }

  ctx.oidc.entity('AuthorizationCode', code);

  const account = await ctx.oidc.provider.Account.findAccount(ctx, code.accountId, code);

  if (!account) {
    throw new InvalidGrant('authorization code invalid (referenced account not found)');
  }
  ctx.oidc.entity('Account', account);

  const { AccessToken, IdToken, RefreshToken } = ctx.oidc.provider;
  const at = new AccessToken({
    accountId: account.accountId,
    claims: code.claims,
    client: ctx.oidc.client,
    expiresWithSession: code.expiresWithSession,
    grantId: code.grantId,
    gty,
    scope: code.scope,
    sessionUid: code.sessionUid,
    sid: code.sid,
  });

  if (ctx.oidc.client.tlsClientCertificateBoundAccessTokens) {
    const cert = ctx.get('x-ssl-client-cert');

    if (!cert) {
      throw new InvalidGrant('mutual TLS client certificate missing');
    }
    at.setS256Thumbprint(cert);
  }

  at.setAudiences(await audiences(ctx, account.accountId, at, 'access_token'));

  ctx.oidc.entity('AccessToken', at);
  const accessToken = await at.save();

  let refreshToken;
  if (await issueRefreshToken(ctx, ctx.oidc.client, code)) {
    const rt = new RefreshToken({
      accountId: account.accountId,
      acr: code.acr,
      amr: code.amr,
      authTime: code.authTime,
      claims: code.claims,
      client: ctx.oidc.client,
      expiresWithSession: code.expiresWithSession,
      grantId: code.grantId,
      gty,
      nonce: code.nonce,
      resource: code.resource,
      scope: code.scope,
      sessionUid: code.sessionUid,
      sid: code.sid,
    });

    if (ctx.oidc.client.tlsClientCertificateBoundAccessTokens && ctx.oidc.client.tokenEndpointAuthMethod === 'none') {
      const cert = ctx.get('x-ssl-client-cert');
      // cert presence is already checked in the access token block
      rt.setS256Thumbprint(cert);
    }

    ctx.oidc.entity('RefreshToken', rt);
    refreshToken = await rt.save();
  }

  let idToken;
  if (code.scopes.has('openid')) {
    const claims = get(code, 'claims.id_token', {});
    const rejected = get(code, 'claims.rejected', []);
    const token = new IdToken({
      ...await account.claims('id_token', code.scope, claims, rejected),
      acr: code.acr,
      amr: code.amr,
      auth_time: code.authTime,
    }, { ctx });

    if (conformIdTokenClaims) {
      token.scope = 'openid';
    } else {
      token.scope = code.scope;
    }

    token.mask = claims;
    token.rejected = rejected;

    token.set('nonce', code.nonce);
    token.set('at_hash', accessToken);
    token.set('sid', code.sid);

    idToken = await token.issue();
  }

  ctx.body = {
    access_token: accessToken,
    expires_in: at.expiration,
    id_token: idToken,
    refresh_token: refreshToken,
    scope: code.scope,
    token_type: 'Bearer',
  };

  await next();
};

module.exports.parameters = new Set(['code', 'redirect_uri']);
