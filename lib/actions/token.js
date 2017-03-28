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

    async function supportedGrantTypeCheck(ctx, next) {
      presence(ctx, ['grant_type']);

      const supported = instance(provider).configuration('grantTypes');

      ctx.assert(supported.has(ctx.oidc.params.grant_type), 400, 'unsupported_grant_type', {
        error_description: `unsupported grant_type requested (${ctx.oidc.params.grant_type})`,
      });

      await next();
    },

    async function allowedGrantTypeCheck(ctx, next) {
      ctx.assert(ctx.oidc.client.grantTypeAllowed(ctx.oidc.params.grant_type), 400,
        'restricted_grant_type', {
          error_description: 'requested grant type is restricted to this client',
        });

      await next();
    },

    async function callTokenHandler(ctx, next) {
      debug('accepted uuid=%s %o', ctx.oidc.uuid, ctx.oidc.params);
      const grantType = ctx.oidc.params.grant_type;

      const { grantTypeHandlers } = instance(provider);
      /* istanbul ignore else */
      if (grantTypeHandlers.has(grantType)) {
        await grantTypeHandlers.get(grantType)(ctx, next);
        provider.emit('grant.success', ctx);
        debug('uuid=%s response %o', ctx.oidc.uuid, ctx.body);
      } else {
        ctx.throw(500, 'server_error', {
          error_description: 'not implemented grant type',
        });
      }
    },
  ]);
};
