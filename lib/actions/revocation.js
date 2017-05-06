'use strict';

const compose = require('koa-compose');
const debug = require('debug')('oidc-provider:revocation');

const PARAM_LIST = new Set(['token', 'token_type_hint']);

const errors = require('../helpers/errors');
const presence = require('../helpers/validate_presence');
const authAndParams = require('../shared/chains/client_auth');

module.exports = function revocationAction(provider) {
  function getAccessToken(token) {
    return provider.AccessToken.find(token);
  }

  function getClientCredentials(token) {
    return provider.ClientCredentials.find(token);
  }

  function getRefreshToken(token) {
    return provider.RefreshToken.find(token);
  }

  function findResult(results) {
    return results.find(found => !!found);
  }

  return compose([

    authAndParams(provider, PARAM_LIST, 'revocation'),

    function* validateTokenPresence(next) {
      presence.call(this, ['token']);
      yield next;
    },

    function* renderTokenResponse(next) {
      this.body = {};
      debug('uuid=%s client=%s token=%s',
        this.oidc.uuid,
        this.oidc.client.clientId,
        this.oidc.params.token);
      yield next;
    },

    function* revokeToken() {
      let tryhard;
      const params = this.oidc.params;

      switch (params.token_type_hint) {
        case 'access_token':
          tryhard = getAccessToken(params.token)
            .then((result) => {
              if (result) return result;
              return Promise.all([
                getClientCredentials(params.token),
                getRefreshToken(params.token),
              ]).then(findResult);
            });
          break;
        case 'client_credentials':
          tryhard = getClientCredentials(params.token)
            .then((result) => {
              if (result) return result;
              return Promise.all([
                getAccessToken(params.token),
                getRefreshToken(params.token),
              ]).then(findResult);
            });
          break;
        case 'refresh_token':
          tryhard = getRefreshToken(params.token)
            .then((result) => {
              if (result) return result;
              return Promise.all([
                getAccessToken(params.token),
                getClientCredentials(params.token),
              ]).then(findResult);
            });
          break;
        default:
          tryhard = Promise.all([
            getAccessToken(params.token),
            getClientCredentials(params.token),
            getRefreshToken(params.token),
          ]).then(findResult);
      }

      let token;
      try {
        token = yield tryhard;
      } catch (err) {
        if (err.message !== 'invalid_token') {
          throw err;
        }
      }

      if (!token) return;

      switch (token.kind) {
        case 'AccessToken':
        case 'ClientCredentials':
        case 'RefreshToken':

          this.assert(token.clientId === this.oidc.client.clientId,
            new errors.InvalidRequestError('this token does not belong to you'));

          yield token.destroy();

          break;
        default:
          this.throw(400, 'unsupported_token_type', {
            error_description: 'revocation of the presented token type is not supported',
          });
      }
    },
  ]);
};
