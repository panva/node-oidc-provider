'use strict';

let compose = require('koa-compose');

const PARAM_LIST = [
  'token',
];

let presence = require('../helpers/validate_presence');
let authAndParams = require('../middlewares/chains/client_auth');

module.exports = function(provider) {

  let ClaimsMask = require('../helpers/claims_mask')(provider.configuration);

  return compose([

    authAndParams(provider, PARAM_LIST),

    function * (next) {
      presence.call(this, ['token']);
      yield next;
    },

    function * renderTokenResponse(next) {
      let payload;
      let token;
      let params = this.oidc.params;

      this.body = {
        active: false,
      };

      try {
        payload = provider.OAuthToken.decode(params.token).payload;

        Object.assign(this.body, {
          exp: payload.exp,
          iat: payload.iat,
          iss: payload.iss,
          jti: payload.jti,
          scope: payload.scope,
        });

        switch (payload.kind) {
        case 'AccessToken':
          this.body.token_type = 'access_token';
          token = yield provider.AccessToken.find(params.token, {
            ignoreExpiration: true,
          });

          break;
        case 'ClientCredentials':
          this.body.token_type = 'client_credentials';
          token = yield provider.ClientCredentials.find(params.token, {
            ignoreExpiration: true,
          });

          break;
        case 'RefreshToken':
          this.body.token_type = 'refresh_token';
          token = yield provider.RefreshToken.find(params.token, {
            ignoreExpiration: true,
          });

          break;
        }
      } catch (err) {}

      if (!token) {
        return;
      }

      Object.assign(this.body, {
        active: token.isValid,
        client_id: token.clientId,
        exp: token.exp,
        iat: token.iat,
        iss: token.iss,
        jti: token.jti,
        scope: token.scope,
        sub: ClaimsMask.sub(token.accountId, this.oidc.client.sectorIdentifier),
      });

      yield next;
    },
  ]);
};
