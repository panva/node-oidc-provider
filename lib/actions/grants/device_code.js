const { get, upperFirst, camelCase } = require('lodash');
const uuidToGrantId = require('debug')('oidc-provider:uuid');

const errors = require('../../helpers/errors');
const presence = require('../../helpers/validate_presence');
const instance = require('../../helpers/weak_cache');
const getCheckPKCE = require('../../helpers/pkce');

const { InvalidGrant, ExpiredToken, AuthorizationPending } = errors;

const gty = 'device_code';

module.exports.handler = function getDeviceCodeHandler(provider) {
  const {
    features: { alwaysIssueRefresh, conformIdTokenClaims }, audiences,
  } = instance(provider).configuration();
  const checkPKCE = getCheckPKCE(provider);

  return async function authorizationCodeResponse(ctx, next) {
    presence(ctx, 'device_code');

    const code = await provider.DeviceCode.find(ctx.oidc.params.device_code, {
      ignoreExpiration: true,
    });

    if (!code) {
      throw new InvalidGrant('device code not found');
    }
    uuidToGrantId('switched from uuid=%s to value of grantId=%s', ctx.oidc.uuid, code.grantId);
    ctx.oidc.uuid = code.grantId;

    checkPKCE(ctx.oidc.params.code_verifier, code.codeChallenge, code.codeChallengeMethod);

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

    const account = await provider.Account.findById(ctx, code.accountId, code);

    if (!account) {
      throw new InvalidGrant('device code invalid (referenced account not found)');
    }
    ctx.oidc.entity('Account', account);

    const { AccessToken, IdToken, RefreshToken } = provider;
    const at = new AccessToken({
      gty,
      accountId: account.accountId,
      claims: code.claims,
      client: ctx.oidc.client,
      grantId: code.grantId,
      scope: code.scope,
      sid: code.sid,
    });

    if (ctx.oidc.client.tlsClientCertificateBoundAccessTokens) {
      const cert = ctx.get('x-ssl-client-cert');

      if (!cert) {
        throw new InvalidGrant('MTLS client certificate missing');
      }
      at.setS256Thumbprint(cert);
    }

    at.setAudiences(await audiences(ctx, account.accountId, at, 'access_token'));

    const accessToken = await at.save();
    ctx.oidc.entity('AccessToken', at);

    let refreshToken;
    const grantPresent = ctx.oidc.client.grantTypes.includes('refresh_token');

    if (grantPresent && (alwaysIssueRefresh || code.scope.split(' ').includes('offline_access'))) {
      const rt = new RefreshToken({
        client: ctx.oidc.client,
        gty,
        accountId: account.accountId,
        acr: code.acr,
        amr: code.amr,
        authTime: code.authTime,
        claims: code.claims,
        grantId: code.grantId,
        nonce: code.nonce,
        scope: code.scope,
        sid: code.sid,
      });

      refreshToken = await rt.save();
      ctx.oidc.entity('RefreshToken', rt);
    }

    const claims = get(code, 'claims.id_token', {});
    const rejected = get(code, 'claims.rejected', []);
    const token = new IdToken({
      ...await account.claims('id_token', code.scope, claims, rejected),
      ...{
        acr: code.acr,
        amr: code.amr,
        auth_time: code.authTime,
      },
    }, ctx.oidc.client);

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

    const idToken = await token.sign({
      audiences: await audiences(ctx, code.accountId, token, 'id_token'),
    });

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
};

module.exports.parameters = new Set(['device_code']);
