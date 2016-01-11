'use strict';

let compose = require('koa-compose');

const PARAM_LIST = [
  'token',
];

let presence = require('../helpers/validate_presence');
let authAndParams = require('../middlewares/chains/client_auth');

module.exports = function (provider) {

  return compose([

    authAndParams(provider, PARAM_LIST),

    function * (next) {
      presence.call(this, ['token']);
      yield next;
    },

    function * renderTokenResponse(next) {
      this.body = {};
      yield next;
    },

    function * revokeToken() {
      let payload;
      let params = this.oidc.params;

      try {
        payload = provider.OAuthToken.decode(params.token).payload;
      } catch (err) {
        return;
      }

      switch (payload.kind) {
      case 'AccessToken':
        try {
          let token = yield provider.AccessToken.find(params.token);
          yield token.destroy();
        } catch (err) {
          return;
        }

        break;
      case 'ClientCredentials':
        try {
          let token = yield provider.ClientCredentials.find(params.token);
          yield token.destroy();
        } catch (err) {
          return;
        }

        break;
      case 'RefreshToken':
        try {
          let token = yield provider.RefreshToken.find(params.token);
          yield token.destroy();
        } catch (err) {
          return;
        }

        break;
      default:
        this.throw(400, 'unsupported_token_type', {
          error_description:
            'revocation of the presented token type is not supported'
        });
      }
    },
  ]);
};
