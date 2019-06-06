const { get, upperFirst, camelCase } = require('lodash');
const uidToGrantId = require('debug')('oidc-provider:uid');

const errors = require('../../helpers/errors');
const presence = require('../../helpers/validate_presence');
const instance = require('../../helpers/weak_cache');

const { InvalidGrant, ExpiredToken, AuthorizationPending } = errors;

const gty = 'device_code';

module.exports.handler = async function deviceCodeHandler(ctx, next) {
  presence(ctx, 'device_code');

  const {
    issueRefreshToken,
    conformIdTokenClaims,
    audiences,
  } = instance(ctx.oidc.provider).configuration();

  const code = await ctx.oidc.provider.DeviceCode.find(ctx.oidc.params.device_code, {
    ignoreExpiration: true,
  });

  if (!code) {
    throw new InvalidGrant('device code not found');
  }

  uidToGrantId('switched from uid=%s to value of grantId=%s', ctx.oidc.uid, code.grantId);
  ctx.oidc.uid = code.grantId;

  if (code.clientId !== ctx.oidc.client.clientId) {
    throw new InvalidGrant('device code client mismatch');
  }

  if (code.isExpired) {
    throw new ExpiredToken('device code is expired');
  }

  if (!code.accountId && !code.error) {
    throw new AuthorizationPending();
  }

  try {
    if (code.consumed) {
      throw new InvalidGrant('device code already consumed');
    }

    await code.consume();
  } catch (err) {
    await code.destroy();
    throw err;
  }

  if (code.error) {
    const className = upperFirst(camelCase(code.error));
    if (errors[className]) {
      throw new errors[className](code.errorDescription);
    } else {
      ctx.status = 400;
      ctx.body = {
        error: code.error,
        error_description: code.errorDescription,
      };
      return next();
    }
  }

  ctx.oidc.entity('DeviceCode', code);

  const account = await ctx.oidc.provider.Account.findAccount(ctx, code.accountId, code);

  if (!account) {
    throw new InvalidGrant('device code invalid (referenced account not found)');
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
      rotations: 0,
      scope: code.scope,
      sessionUid: code.sessionUid,
      sid: code.sid,
    });

    ctx.oidc.entity('RefreshToken', rt);
    refreshToken = await rt.save();
  }


  let idToken;
  if (code.scopes.has('openid')) {
    const claims = get(code, 'claims.id_token', {});
    const rejected = get(code, 'claims.rejected', []);
    const token = new IdToken({
      ...await account.claims('id_token', code.scope, claims, rejected),
      ...{
        acr: code.acr,
        amr: code.amr,
        auth_time: code.authTime,
      },
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

  return next();
};

module.exports.parameters = new Set(['device_code']);
