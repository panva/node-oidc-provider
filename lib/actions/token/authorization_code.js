const { get } = require('lodash');
const assert = require('assert');
const base64url = require('base64url');
const crypto = require('crypto');
const { InvalidGrantError } = require('../../helpers/errors');
const presence = require('../../helpers/validate_presence');
const instance = require('../../helpers/weak_cache');

module.exports.handler = function getAuthorizationCodeHandler(provider) {
  const pkce = instance(provider).configuration('features.pkce');
  const mixupMitigation = instance(provider).configuration('features.mixupMitigation');
  return async function authorizationCodeResponse(ctx, next) {
    presence(ctx, ['code', 'redirect_uri']);

    const code = await provider.AuthorizationCode.find(ctx.oidc.params.code, {
      ignoreExpiration: true,
    });

    if (!code) {
      ctx.throw(new InvalidGrantError('authorization code not found'));
    }

    if (code.isExpired) {
      ctx.throw(new InvalidGrantError('authorization code is expired'));
    }

    // PKCE check
    if (pkce && (ctx.oidc.params.code_verifier || code.codeChallenge)) {
      try {
        let expected = ctx.oidc.params.code_verifier;
        assert(expected);

        if (code.codeChallengeMethod === 'S256') {
          expected = base64url(crypto.createHash('sha256').update(expected).digest());
        }

        assert.equal(code.codeChallenge, expected);
      } catch (err) {
        ctx.throw(new InvalidGrantError('PKCE verification failed'));
      }
    }

    try {
      if (code.consumed) {
        ctx.throw(new InvalidGrantError('authorization code already consumed'));
      }

      await code.consume();
    } catch (err) {
      await code.destroy();
      throw err;
    }

    if (mixupMitigation && code.state !== ctx.oidc.params.state) {
      ctx.throw(new InvalidGrantError('state mismatch'));
    }

    if (code.clientId !== ctx.oidc.client.clientId) {
      ctx.throw(new InvalidGrantError('authorization code client mismatch'));
    }

    if (code.redirectUri !== ctx.oidc.params.redirect_uri) {
      ctx.throw(new InvalidGrantError('authorization code redirect_uri mismatch'));
    }

    const account = await provider.Account.findById(ctx, code.accountId, code);

    if (!account) {
      ctx.throw(new InvalidGrantError('authorization code invalid (referenced account not found)'));
    }

    const { AccessToken, IdToken, RefreshToken } = provider;
    const at = new AccessToken({
      accountId: account.accountId,
      claims: code.claims,
      clientId: ctx.oidc.client.clientId,
      grantId: code.grantId,
      scope: code.scope,
      sid: code.sid,
    });

    const accessToken = await at.save();
    const { expiresIn } = AccessToken;

    let refreshToken;
    const grantPresent = ctx.oidc.client.grantTypes.includes('refresh_token');
    const shouldIssue = instance(provider).configuration('features.alwaysIssueRefresh') ||
      code.scope.split(' ').includes('offline_access');

    if (grantPresent && shouldIssue) {
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

    const token = new IdToken(Object.assign({}, await Promise.resolve(account.claims()), {
      acr: code.acr,
      amr: code.amr,
      auth_time: code.authTime,
    }), ctx.oidc.client.sectorIdentifier);

    token.scope = code.scope;
    token.mask = get(code.claims, 'id_token', {});

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
      token_type: 'Bearer',
    };

    await next();
  };
};

module.exports.parameters = ['code', 'redirect_uri', 'code_verifier', 'state'];
