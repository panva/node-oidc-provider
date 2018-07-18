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
      ctx.throw(new InvalidGrant('device code not found'));
    }
    uuidToGrantId('switched from uuid=%s to value of grantId=%s', ctx.oidc.uuid, code.grantId);
    ctx.oidc.uuid = code.grantId;

    checkPKCE(ctx.oidc.params.code_verifier, code.codeChallenge, code.codeChallengeMethod);

    if (code.clientId !== ctx.oidc.client.clientId) {
      ctx.throw(new InvalidGrant('device code client mismatch'));
    }

    if (code.isExpired) {
      ctx.throw(new ExpiredToken('device code is expired'));
    }

    if (!code.accountId && !code.error) {
      ctx.throw(new AuthorizationPending());
    }

    try {
      if (code.consumed) {
        ctx.throw(new InvalidGrant('device code already consumed'));
      }

      await code.consume();
    } catch (err) {
      await code.destroy();
      throw err;
    }

    if (code.error) {
      const className = upperFirst(camelCase(code.error));
      if (errors[className]) {
        ctx.throw(new errors[className](code.errorDescription));
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
      ctx.throw(new InvalidGrant('device code invalid (referenced account not found)'));
    }
    ctx.oidc.entity('Account', account);

    const { AccessToken, IdToken, RefreshToken } = provider;
    const at = new AccessToken({
      gty,
      accountId: account.accountId,
      claims: code.claims,
      clientId: ctx.oidc.client.clientId,
      grantId: code.grantId,
      scope: code.scope,
      sid: code.sid,
    });

    at.setAudiences(await audiences(ctx, account.accountId, at, 'access_token', code.scope));

    const accessToken = await at.save();
    ctx.oidc.entity('AccessToken', at);

    const { expiresIn } = AccessToken;

    let refreshToken;
    const grantPresent = ctx.oidc.client.grantTypes.includes('refresh_token');

    if (grantPresent && (alwaysIssueRefresh || code.scope.split(' ').includes('offline_access'))) {
      const rt = new RefreshToken({
        gty,
        accountId: account.accountId,
        acr: code.acr,
        amr: code.amr,
        authTime: code.authTime,
        claims: code.claims,
        clientId: ctx.oidc.client.clientId,
        grantId: code.grantId,
        nonce: code.nonce,
        scope: code.scope,
        sid: code.sid,
      });

      refreshToken = await rt.save();
      ctx.oidc.entity('RefreshToken', rt);
    }

    const token = new IdToken({
      ...await account.claims('id_token', code.scope),
      ...{
        acr: code.acr,
        amr: code.amr,
        auth_time: code.authTime,
      },
    }, ctx.oidc.client.sectorIdentifier);

    if (conformIdTokenClaims) {
      token.scope = 'openid';
    } else {
      token.scope = code.scope;
    }
    token.mask = get(code.claims, 'id_token', {});

    token.set('nonce', code.nonce);
    token.set('at_hash', accessToken);
    token.set('sid', code.sid);

    const idToken = await token.sign(ctx.oidc.client, {
      audiences: await audiences(ctx, code.accountId, code, 'id_token', code.scope),
    });

    ctx.body = {
      access_token: accessToken,
      expires_in: expiresIn,
      id_token: idToken,
      refresh_token: refreshToken,
      scope: code.scope,
      token_type: 'Bearer',
    };

    return next();
  };
};

module.exports.parameters = ['device_code', 'code_verifier'];
