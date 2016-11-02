'use strict';

const compose = require('koa-compose');

const PARAM_LIST = new Set(['token', 'token_type_hint']);

const presence = require('../helpers/validate_presence');
const authAndParams = require('../shared/chains/client_auth');
const noCache = require('../shared/no_cache');
const mask = require('../helpers/claims');
const instance = require('../helpers/weak_cache');

module.exports = function introspectionAction(provider) {
  const Claims = mask(instance(provider).configuration());

  function getAccessToken(token) {
    return provider.AccessToken.find(token, {
      ignoreExpiration: true,
    });
  }

  function getClientCredentials(token) {
    return provider.ClientCredentials.find(token, {
      ignoreExpiration: true,
    });
  }

  function getRefreshToken(token) {
    return provider.RefreshToken.find(token, {
      ignoreExpiration: true,
    });
  }

  function findResult(results) {
    return results.find(found => !!found);
  }

  return compose([

    noCache,

    authAndParams(provider, PARAM_LIST),

    function* validateTokenPresence(next) {
      presence.call(this, ['token']);
      yield next;
    },

    function* renderTokenResponse(next) {
      let token;
      const params = this.oidc.params;

      this.body = { active: false };

      let tryhard;

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

      try {
        token = yield tryhard;

        switch (token && token.kind) {
          case 'AccessToken':
            this.body.token_type = 'access_token';
            break;
          case 'ClientCredentials':
            this.body.token_type = 'client_credentials';
            break;
          case 'RefreshToken':
            this.body.token_type = 'refresh_token';
            break;
          default:
            return;
        }
      } catch (err) {}

      if (!this.body.token_type) {
        return;
      }

      if (token.clientId !== this.oidc.client.clientId) {
        this.body.sub = Claims.sub(token.accountId,
          (yield provider.Client.find(token.clientId)).sectorIdentifier);
      } else {
        this.body.sub = Claims.sub(token.accountId, this.oidc.client.sectorIdentifier);
      }

      Object.assign(this.body, {
        active: token.isValid,
        client_id: token.clientId,
        exp: token.exp,
        iat: token.iat,
        sid: token.sid,
        iss: token.iss,
        jti: token.jti,
        scope: token.scope,
      });

      yield next;
    },
  ]);
};
