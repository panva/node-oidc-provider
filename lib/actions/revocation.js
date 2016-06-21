'use strict';

const compose = require('koa-compose');

const PARAM_LIST = [
  'token',
];

const presence = require('../helpers/validate_presence');
const authAndParams = require('../middlewares/chains/client_auth');

module.exports = function revocationAction(provider) {
  return compose([

    authAndParams(provider, PARAM_LIST),

    function * validateTokenPresence(next) {
      presence.call(this, ['token']);
      yield next;
    },

    function * renderTokenResponse(next) {
      this.body = {};
      yield next;
    },

    function * revokeToken() {
      let payload;
      const params = this.oidc.params;

      try {
        payload = provider.OAuthToken.decode(params.token).decoded;
      } catch (err) {
        return;
      }

      switch (payload.kind) {
        case 'AccessToken':
          try {
            const token = yield provider.AccessToken.find(params.token);
            yield token.destroy();
          } catch (err) {
            return;
          }

          break;
        case 'ClientCredentials':
          try {
            const token = yield provider.ClientCredentials.find(params.token);
            yield token.destroy();
          } catch (err) {
            return;
          }

          break;
        case 'RefreshToken':
          try {
            const token = yield provider.RefreshToken.find(params.token);
            yield token.destroy();
          } catch (err) {
            return;
          }

          break;
        default:
          this.throw(400, 'unsupported_token_type', {
            error_description:
            'revocation of the presented token type is not supported',
          });
      }
    },
  ]);
};
