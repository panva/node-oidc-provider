'use strict';

const _ = require('lodash');
const errors = require('../../helpers/errors');
const presence = require('../../helpers/validate_presence');

module.exports.handler = function getAuthorizationCodeHandler(provider) {
  return function * authorizationCodeResponse(next) {
    presence.call(this, ['code', 'redirect_uri']);

    const code = yield provider.get('AuthorizationCode').find(this.oidc.params.code, {
      ignoreExpiration: true,
    });

    this.assert(code, new errors.InvalidGrantError('authorization code not found'));
    this.assert(!code.isExpired, new errors.InvalidGrantError('authorization code is expired'));

    try {
      this.assert(!code.consumed,
      new errors.InvalidGrantError('authorization code already consumed'));

      yield code.consume();
    } catch (err) {
      yield code.destroy();
      throw err;
    }

    this.assert(code.clientId === this.oidc.client.clientId,
      new errors.InvalidGrantError('authorization code client mismatch'));

    this.assert(code.redirectUri === this.oidc.params.redirect_uri,
      new errors.InvalidGrantError('authorization code redirect_uri mismatch'));

    const account = yield provider.get('Account').findById(code.accountId);

    this.assert(account,
      new errors.InvalidGrantError('authorization code invalid (referenced account not found)'));

    const AccessToken = provider.get('AccessToken');
    const at = new AccessToken({
      accountId: account.accountId,
      claims: code.claims,
      clientId: this.oidc.client.clientId,
      grantId: code.grantId,
      scope: code.scope,
    });

    const accessToken = yield at.save();
    const tokenType = 'Bearer';
    const expiresIn = AccessToken.expiresIn;

    let refreshToken;
    const clientAllowed = this.oidc.client.grantTypes.indexOf('refresh_token') !== -1;
    const grantAllowed = provider.configuration('features.refreshToken') ||
      code.scope.split(' ').indexOf('offline_access') !== -1;

    if (clientAllowed && grantAllowed) {
      const RefreshToken = provider.get('RefreshToken');
      const rt = new RefreshToken({
        accountId: account.accountId,
        acr: code.acr,
        authTime: code.authTime,
        claims: code.claims,
        clientId: this.oidc.client.clientId,
        grantId: code.grantId,
        scope: code.scope,
      });

      refreshToken = yield rt.save();
    }

    const IdToken = provider.get('IdToken');
    const token = new IdToken(Object.assign({}, account.claims(), {
      acr: code.acr,
      auth_time: code.authTime,
    }), this.oidc.client.sectorIdentifier);

    token.scope = code.scope;
    token.mask = _.get(code.claims, 'id_token', {});

    token.set('at_hash', accessToken);
    token.set('nonce', code.nonce);
    token.set('rt_hash', refreshToken);

    const idToken = yield token.sign(this.oidc.client);

    this.body = {
      access_token: accessToken,
      expires_in: expiresIn,
      id_token: idToken,
      refresh_token: refreshToken,
      token_type: tokenType,
    };

    yield next;
  };
};

module.exports.parameters = ['code', 'redirect_uri'];
