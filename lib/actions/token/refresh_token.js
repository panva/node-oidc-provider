'use strict';


const _ = require('lodash');
const errors = require('../../helpers/errors');
const presence = require('../../helpers/validate_presence');
const instance = require('../../helpers/weak_cache');

module.exports.handler = function getRefreshTokenHandler(provider) {
  return function* refreshTokenResponse(next) {
    presence.call(this, ['refresh_token']);

    const RefreshToken = provider.RefreshToken;
    const Account = provider.Account;
    const AccessToken = provider.AccessToken;
    const IdToken = provider.IdToken;

    let refreshTokenValue = this.oidc.params.refresh_token;
    let refreshToken = yield RefreshToken.find(refreshTokenValue, { ignoreExpiration: true });

    if (this.oidc.nativeAuthSkip) {
      this.assert(refreshToken && refreshToken.onlyPKCE,
        new errors.InvalidClientError('pkce for refresh token assumed but was not used'));
    }

    this.assert(refreshToken, new errors.InvalidGrantError('refresh token not found'));
    this.assert(!refreshToken.isExpired, new errors.InvalidGrantError('refresh token is expired'));
    this.assert(refreshToken.clientId === this.oidc.client.clientId,
      new errors.InvalidGrantError('refresh token client mismatch'));

    const refreshTokenScopes = refreshToken.scope.split(' ');

    if (this.oidc.params.scope) {
      const missing = _.difference(this.oidc.params.scope.split(' '), refreshTokenScopes);

      this.assert(_.isEmpty(missing), 400, 'invalid_scope', {
        error_description: 'refresh token missing requested scope',
        scope: missing.join(' '),
      });
    }

    const account = yield Account.findById.call(this, refreshToken.accountId);

    this.assert(account,
      new errors.InvalidGrantError('refresh token invalid (referenced account not found)'));

    if (instance(provider).configuration('refreshTokenRotation') === 'rotateAndConsume') {
      try {
        this.assert(!refreshToken.consumed,
          new errors.InvalidGrantError('refresh token already used'));

        yield refreshToken.consume();

        refreshToken = new RefreshToken(Object.assign({}, {
          accountId: refreshToken.accountId,
          acr: refreshToken.acr,
          amr: refreshToken.amr,
          authTime: refreshToken.authTime,
          claims: refreshToken.claims,
          clientId: refreshToken.clientId,
          grantId: refreshToken.grantId,
          nonce: refreshToken.nonce,
          scope: this.oidc.params.scope || refreshToken.scope,
          sid: refreshToken.sid,
        }));

        refreshTokenValue = yield refreshToken.save();
      } catch (err) {
        yield refreshToken.destroy();
        throw err;
      }
    }

    const at = new AccessToken({
      accountId: account.accountId,
      claims: refreshToken.claims,
      clientId: this.oidc.client.clientId,
      grantId: refreshToken.grantId,
      scope: this.oidc.params.scope || refreshToken.scope,
      sid: refreshToken.sid,
    });

    const accessToken = yield at.save();
    const tokenType = 'Bearer';
    const expiresIn = AccessToken.expiresIn;

    const token = new IdToken(Object.assign({}, yield Promise.resolve(account.claims()), {
      acr: refreshToken.acr,
      amr: refreshToken.amr,
      auth_time: refreshToken.authTime,
    }), this.oidc.client.sectorIdentifier);

    token.scope = refreshToken.scope;
    token.mask = _.get(refreshToken.claims, 'id_token', {});

    token.set('nonce', refreshToken.nonce);
    token.set('at_hash', accessToken);
    token.set('rt_hash', refreshTokenValue);
    token.set('sid', refreshToken.sid);

    const idToken = yield token.sign(this.oidc.client);

    this.body = {
      access_token: accessToken,
      expires_in: expiresIn,
      id_token: idToken,
      refresh_token: refreshTokenValue,
      token_type: tokenType,
    };

    yield next;
  };
};

module.exports.parameters = ['refresh_token', 'scope'];
