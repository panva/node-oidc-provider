'use strict';


const _ = require('lodash');
const errors = require('../../helpers/errors');
const presence = require('../../helpers/validate_presence');

module.exports.handler = function getRefreshTokenHandler(provider) {
  return async function refreshTokenResponse(ctx, next) {
    presence.call(ctx, ['refresh_token']);

    const RefreshToken = provider.RefreshToken;
    const Account = provider.Account;
    const AccessToken = provider.AccessToken;
    const IdToken = provider.IdToken;

    const refreshToken = await RefreshToken.find(
      ctx.oidc.params.refresh_token, {
        ignoreExpiration: true,
      });

    ctx.assert(refreshToken, new errors.InvalidGrantError('refresh token not found'));
    ctx.assert(!refreshToken.isExpired, new errors.InvalidGrantError('refresh token is expired'));
    ctx.assert(refreshToken.clientId === ctx.oidc.client.clientId,
      new errors.InvalidGrantError('refresh token client mismatch'));

    const refreshTokenScopes = refreshToken.scope.split(' ');

    if (ctx.oidc.params.scope) {
      const missing = _.difference(ctx.oidc.params.scope.split(' '), refreshTokenScopes);

      ctx.assert(_.isEmpty(missing), 400, 'invalid_scope', {
        error_description: 'refresh token missing requested scope',
        scope: missing.join(' '),
      });
    }

    const account = await Account.findById(refreshToken.accountId);

    ctx.assert(account,
      new errors.InvalidGrantError('refresh token invalid (referenced account not found)'));

    const at = new AccessToken({
      accountId: account.accountId,
      claims: refreshToken.claims,
      clientId: ctx.oidc.client.clientId,
      grantId: refreshToken.grantId,
      scope: ctx.oidc.params.scope || refreshToken.scope,
      sid: refreshToken.sid,
    });

    const accessToken = await at.save();
    const tokenType = 'Bearer';
    const expiresIn = AccessToken.expiresIn;

    const token = new IdToken(Object.assign({}, account.claims(), {
      acr: refreshToken.acr,
      auth_time: refreshToken.authTime,
    }), ctx.oidc.client.sectorIdentifier);

    token.scope = refreshToken.scope;
    token.mask = _.get(refreshToken.claims, 'id_token', {});

    token.set('nonce', refreshToken.nonce);
    token.set('at_hash', accessToken);
    token.set('rt_hash', ctx.oidc.params.refresh_token);
    token.set('sid', refreshToken.sid);

    const idToken = await token.sign(ctx.oidc.client);

    ctx.body = {
      access_token: accessToken,
      expires_in: expiresIn,
      id_token: idToken,
      refresh_token: ctx.oidc.params.refresh_token,
      token_type: tokenType,
    };

    await next();
  };
};

module.exports.parameters = ['refresh_token', 'scope'];
