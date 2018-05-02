const compose = require('koa-compose');
const debug = require('debug')('oidc-provider:token');

const presence = require('../helpers/validate_presence');
const instance = require('../helpers/weak_cache');
const {
  InvalidRequest,
  UnsupportedGrantType,
  RestrictedGrantType,
} = require('../helpers/errors');

const noCache = require('../shared/no_cache');
const authAndParams = require('../shared/token_auth');

module.exports = function tokenAction(provider) {
  return compose([
    noCache,

    authAndParams(provider, instance(provider).grantTypeWhitelist, 'token'),

    async function supportedGrantTypeCheck(ctx, next) {
      presence(ctx, ['grant_type']);

      const supported = instance(provider).configuration('grantTypes');

      if (!supported.has(ctx.oidc.params.grant_type)) {
        ctx.throw(new UnsupportedGrantType());
      }

      await next();
    },

    async function allowedGrantTypeCheck(ctx, next) {
      if (!ctx.oidc.client.grantTypeAllowed(ctx.oidc.params.grant_type)) {
        ctx.throw(new RestrictedGrantType());
      }

      await next();
    },

    async function implicitCheck(ctx, next) {
      if (ctx.oidc.params.grant_type === 'implicit') {
        ctx.throw(new InvalidRequest('implicit is not a grant resolved with a token endpoint call'));
      }

      await next();
    },

    async function callTokenHandler(ctx, next) {
      debug('accepted uuid=%s %o', ctx.oidc.uuid, ctx.oidc.params);
      const grantType = ctx.oidc.params.grant_type;

      const { grantTypeHandlers } = instance(provider);

      await grantTypeHandlers.get(grantType)(ctx, next);
      provider.emit('grant.success', ctx);
      debug('response uuid=%s %o', ctx.oidc.uuid, ctx.body);
    },
  ]);
};
