'use strict';

const compose = require('koa-compose');

const presence = require('../helpers/validate_presence');
const authAndParams = require('../middlewares/chains/client_auth');

module.exports = function tokenAction(provider) {
  return compose([

    authAndParams(provider, provider.grantTypeWhitelist),

    function * supportedGrantTypeCheck(next) {
      presence.call(this, ['grant_type']);

      const supported = provider.configuration('grantTypes');

      this.assert(supported.has(this.oidc.params.grant_type), 400, 'unsupported_grant_type', {
        error_description: `unsupported grant_type requested (${this.oidc.params.grant_type})`,
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
      const grantType = this.oidc.params.grant_type;

      /* istanbul ignore else */
      if (provider.grantTypeHandlers.has(grantType)) {
        yield provider.grantTypeHandlers.get(grantType).call(this, next);
        provider.emit('grant.success', this);
      } else {
        this.throw(500, 'server_error', {
          error_description: 'not implemented grant type',
        });
      }
    },
  ]);
};
