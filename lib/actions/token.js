'use strict';

const compose = require('koa-compose');
const debug = require('debug')('oidc-provider:token');

const presence = require('../helpers/validate_presence');
const instance = require('../helpers/weak_cache');

const noCache = require('../shared/no_cache');
const authAndParams = require('../shared/chains/client_auth');

module.exports = function tokenAction(provider) {
  return compose([
    noCache,

    authAndParams(provider, instance(provider).grantTypeWhitelist, 'token'),

    function* supportedGrantTypeCheck(next) {
      presence.call(this, ['grant_type']);

      const supported = instance(provider).configuration('grantTypes');

      this.assert(supported.has(this.oidc.params.grant_type), 400, 'unsupported_grant_type', {
        error_description: `unsupported grant_type requested (${this.oidc.params.grant_type})`,
      });

      yield next;
    },

    function* allowedGrantTypeCheck(next) {
      const oidc = this.oidc;

      this.assert(oidc.client.grantTypeAllowed(oidc.params.grant_type), 400,
        'restricted_grant_type', {
          error_description: 'requested grant type is restricted to this client',
        });

      yield next;
    },

    function* callTokenHandler(next) {
      debug('accepted uuid=%s %o', this.oidc.uuid, this.oidc.params);
      const grantType = this.oidc.params.grant_type;

      const grantTypeHandlers = instance(provider).grantTypeHandlers;
      /* istanbul ignore else */
      if (grantTypeHandlers.has(grantType)) {
        yield grantTypeHandlers.get(grantType).call(this, next);
        provider.emit('grant.success', this);
        debug('uuid=%s response %o', this.oidc.uuid, this.body);
      } else {
        this.throw(500, 'server_error', {
          error_description: 'not implemented grant type',
        });
      }
    },
  ]);
};
