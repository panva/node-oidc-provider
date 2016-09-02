'use strict';


const _ = require('lodash');
const errors = require('../../helpers/errors');
const presence = require('../../helpers/validate_presence');

module.exports.handler = function getRefreshTokenHandler(provider) {
  return function * refreshTokenResponse(next) {
    presence.call(this, ['refresh_token']);

    const RefreshToken = provider.get('RefreshToken');
    const Account = provider.get('Account');
    const AccessToken = provider.get('AccessToken');
    const IdToken = provider.get('IdToken');

    const refreshToken = yield RefreshToken.find(
      this.oidc.params.refresh_token, {
        ignoreExpiration: true,
      });

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

    const account = yield Account.findById(refreshToken.accountId);

    this.assert(account,
      new errors.InvalidGrantError('refresh token invalid (referenced account not found)'));

    const at = new AccessToken({
      accountId: account.accountId,
      claims: refreshToken.claims,
      clientId: this.oidc.client.clientId,
      grantId: refreshToken.grantId,
      scope: this.oidc.params.scope || refreshToken.scope,
    });

    const accessToken = yield at.save();
    const tokenType = 'Bearer';
    const expiresIn = AccessToken.expiresIn;

    const token = new IdToken(Object.assign({}, account.claims(), {
      acr: refreshToken.acr,
      auth_time: refreshToken.authTime,
    }), this.oidc.client.sectorIdentifier);

    token.scope = refreshToken.scope;
    token.mask = _.get(refreshToken.claims, 'id_token', {});

    token.set('nonce', refreshToken.nonce);
    token.set('at_hash', accessToken);
    token.set('rt_hash', this.oidc.params.refresh_token);
    token.set('sid', refreshToken.sid);

    const idToken = yield token.sign(this.oidc.client);

    this.body = {
      access_token: accessToken,
      expires_in: expiresIn,
      id_token: idToken,
      refresh_token: this.oidc.params.refresh_token,
      token_type: tokenType,
    };

    yield next;
  };
};

module.exports.parameters = ['refresh_token', 'scope'];
