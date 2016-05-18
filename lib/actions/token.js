'use strict';

const compose = require('koa-compose');
const _ = require('lodash');

const PARAM_LIST = [
  'client_assertion',
  'client_assertion_type',
  'client_id',
  'client_secret',
  'code',
  'grant_type',
  'redirect_uri',
  'refresh_token',
  'scope',
];

const presence = require('../helpers/validate_presence');
const authAndParams = require('../middlewares/chains/client_auth');

const errors = require('../helpers/errors');

module.exports = function tokenAction(provider) {
  const handlers = {};
  const conf = provider.configuration.grantTypes;

  if (conf.indexOf('authorization_code') !== -1) {
    handlers.authorization_code = function * authorizationCodeResponse(next) {
      presence.call(this, ['code', 'redirect_uri']);

      const code = yield provider.AuthorizationCode.find(this.oidc.params.code, {
        ignoreExpiration: true,
      });

      this.assert(code,
        new errors.InvalidGrantError('authorization code not found'));
      this.assert(!code.isExpired,
        new errors.InvalidGrantError('authorization code is expired'));

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
        new errors.InvalidGrantError(
          'authorization code redirect_uri mismatch'
        ));

      const account = yield provider.Account.findById(code.accountId);

      this.assert(account,
        new errors.InvalidGrantError(
          'authorization code invalid (referenced account not found)'
        ));

      const at = new provider.AccessToken({
        accountId: account.accountId,
        claims: code.claims,
        clientId: this.oidc.client.clientId,
        grantId: code.grantId,
        scope: code.scope,
      });

      const accessToken = yield at.toToken();
      const tokenType = 'Bearer';
      const expiresIn = provider.AccessToken.expiresIn;

      let refreshToken;
      const clientAllowed = this.oidc.client.grantTypes.indexOf('refresh_token') !== -1;
      const grantAllowed = provider.configuration.features.refreshToken ||
          code.scope.split(' ').indexOf('offline_access') !== -1;

      if (clientAllowed && grantAllowed) {
        const rt = new provider.RefreshToken({
          accountId: account.accountId,
          acr: code.acr,
          authTime: code.authTime,
          claims: code.claims,
          clientId: this.oidc.client.clientId,
          grantId: code.grantId,
          scope: code.scope,
        });

        refreshToken = yield rt.toToken();
      }

      const token = new provider.IdToken(Object.assign({}, account.claims(), {
        acr: code.acr,
        auth_time: code.authTime,
      }), this.oidc.client.sectorIdentifier);

      token.scope = code.scope;
      token.mask = _.get(code.claims, 'id_token', {});

      token.set('at_hash', accessToken);
      token.set('nonce', code.nonce);
      token.set('rt_hash', refreshToken);

      const idToken = yield token.toJWT(this.oidc.client);

      this.body = {
        access_token: accessToken,
        expires_in: expiresIn,
        id_token: idToken,
        refresh_token: refreshToken,
        token_type: tokenType,
      };
      yield next;
    };
  }

  if (conf.indexOf('client_credentials') !== -1) {
    handlers.client_credentials = function * clientCredentialsResponse(next) {
      const at = new provider.ClientCredentials({
        clientId: this.oidc.client.clientId,
        scope: this.oidc.params.scope,
      });

      const token = yield at.toToken();
      const tokenType = 'Bearer';
      const expiresIn = provider.ClientCredentials.expiresIn;

      this.body = {
        access_token: token,
        expires_in: expiresIn,
        token_type: tokenType,
      };

      yield next;
    };
  }

  if (conf.indexOf('refresh_token') !== -1) {
    handlers.refresh_token = function * refreshTokenResponse(next) {
      presence.call(this, ['refresh_token']);

      const refreshToken = yield provider.RefreshToken.find(
        this.oidc.params.refresh_token, {
          ignoreExpiration: true,
        });

      this.assert(refreshToken,
        new errors.InvalidGrantError('refresh token not found'));
      this.assert(!refreshToken.isExpired,
        new errors.InvalidGrantError('refresh token is expired'));
      this.assert(refreshToken.clientId === this.oidc.client.clientId,
        new errors.InvalidGrantError('refresh token client mismatch'));

      const refreshTokenScopes = refreshToken.scope.split(' ');

      if (this.oidc.params.scope) {
        const missing = _.difference(this.oidc.params.scope.split(' '),
          refreshTokenScopes);

        this.assert(_.isEmpty(missing), 400, 'invalid_scope', {
          error_description:
            `refresh token not allowed scopes (${missing.join(',')})`,
        });
      }

      const account = yield provider.Account.findById(refreshToken.accountId);

      this.assert(account,
        new errors.InvalidGrantError(
          'refresh token invalid (referenced account not found)'));

      const at = new provider.AccessToken({
        accountId: account.accountId,
        claims: refreshToken.claims,
        clientId: this.oidc.client.clientId,
        grantId: refreshToken.grantId,
        scope: this.oidc.params.scope || refreshToken.scope,
      });

      const accessToken = yield at.toToken();
      const tokenType = 'Bearer';
      const expiresIn = provider.AccessToken.expiresIn;

      const token = new provider.IdToken(Object.assign({}, account.claims(), {
        acr: refreshToken.acr,
        auth_time: refreshToken.authTime,
      }), this.oidc.client.sectorIdentifier);

      token.scope = refreshToken.scope;
      token.mask = _.get(refreshToken.claims, 'id_token', {});

      token.set('at_hash', accessToken);
      token.set('rt_hash', this.oidc.params.refresh_token);

      const idToken = token.toJWT(this.oidc.client);

      this.body = {
        access_token: accessToken,
        expires_in: expiresIn,
        id_token: idToken,
        refresh_token: this.oidc.params.refresh_token,
        token_type: tokenType,
      };

      yield next;
    };
  }

  return compose([

    authAndParams(provider, PARAM_LIST),

    function * supportedGrantTypeCheck(next) {
      presence.call(this, ['grant_type']);

      const supported = provider.configuration.grantTypes;
      const value = supported.indexOf(this.oidc.params.grant_type) !== -1;

      this.assert(value, 400, 'unsupported_grant_type', {
        error_description:
          `unsupported grant_type requested (${this.oidc.params.grant_type})`,
      });

      yield next;
    },

    function * allowedGrantTypeCheck(next) {
      const oidc = this.oidc;

      this.assert(oidc.client.grantTypeAllowed(oidc.params.grant_type), 400,
        'restricted_grant_type', {
          error_description: 'requested grant type is restricted to this client',
        });

      yield next;
    },

    function * callTokenHandler(next) {
      const handler = handlers[this.oidc.params.grant_type];
      if (handler) {
        yield handler.call(this, next);

        provider.emit('grant.success', this);
      } else {
        this.throw(500, 'server_error', {
          error_description: 'not implemented grant type',
        });
      }
    },
  ]);
};
