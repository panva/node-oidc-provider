'use strict';

const _ = require('lodash');
const assert = require('assert');
const base64url = require('base64url');
const crypto = require('crypto');
const errors = require('../../helpers/errors');
const presence = require('../../helpers/validate_presence');
const instance = require('../../helpers/weak_cache');

module.exports.handler = function getAuthorizationCodeHandler(provider) {
  return async function authorizationCodeResponse(ctx, next) {
    presence.call(ctx, ['code', 'redirect_uri']);

    const code = await provider.AuthorizationCode.find(ctx.oidc.params.code, {
      ignoreExpiration: true,
    });

    ctx.assert(code, new errors.InvalidGrantError('authorization code not found'));
    ctx.assert(!code.isExpired, new errors.InvalidGrantError('authorization code is expired'));

    // PKCE check
    if (code.codeChallenge) {
      try {
        assert(ctx.oidc.params.code_verifier);
        let expected = ctx.oidc.params.code_verifier;

        if (code.codeChallengeMethod === 'S256') {
          expected = base64url(crypto.createHash('sha256').update(expected).digest());
        }

        assert.equal(code.codeChallenge, expected);
      } catch (err) {
        ctx.throw(new errors.InvalidGrantError('PKCE verification failed'));
      }
    }

    try {
      ctx.assert(!code.consumed,
        new errors.InvalidGrantError('authorization code already consumed'));

      await code.consume();
    } catch (err) {
      await code.destroy();
      throw err;
    }

    ctx.assert(code.clientId === ctx.oidc.client.clientId,
      new errors.InvalidGrantError('authorization code client mismatch'));

    ctx.assert(code.redirectUri === ctx.oidc.params.redirect_uri,
      new errors.InvalidGrantError('authorization code redirect_uri mismatch'));

    const account = await provider.Account.findById(code.accountId);

    ctx.assert(account,
      new errors.InvalidGrantError('authorization code invalid (referenced account not found)'));

    const AccessToken = provider.AccessToken;
    const at = new AccessToken({
      accountId: account.accountId,
      claims: code.claims,
      clientId: ctx.oidc.client.clientId,
      grantId: code.grantId,
      scope: code.scope,
      sid: code.sid,
    });

    const accessToken = await at.save();
    const tokenType = 'Bearer';
    const expiresIn = AccessToken.expiresIn;

    let refreshToken;
    const grantPresent = ctx.oidc.client.grantTypes.indexOf('refresh_token') !== -1;
    const shouldIssue = instance(provider).configuration('features.refreshToken') ||
      code.scope.split(' ').indexOf('offline_access') !== -1;

    if (grantPresent && shouldIssue) {
      const RefreshToken = provider.RefreshToken;
      const rt = new RefreshToken({
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
    }

    const IdToken = provider.IdToken;
    const token = new IdToken(Object.assign({}, await Promise.resolve(account.claims()), {
      acr: code.acr,
      amr: code.amr,
      auth_time: code.authTime,
    }), ctx.oidc.client.sectorIdentifier);

    token.scope = code.scope;
    token.mask = _.get(code.claims, 'id_token', {});

    token.set('nonce', code.nonce);
    token.set('at_hash', accessToken);
    token.set('rt_hash', refreshToken);
    token.set('sid', code.sid);

    const idToken = await token.sign(ctx.oidc.client);

    ctx.body = {
      access_token: accessToken,
      expires_in: expiresIn,
      id_token: idToken,
      refresh_token: refreshToken,
      token_type: tokenType,
    };

    await next();
  };
};

module.exports.parameters = ['code', 'redirect_uri', 'code_verifier'];
