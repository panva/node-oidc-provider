const debug = require('debug')('oidc-provider:token');

const presence = require('../helpers/validate_presence');
const instance = require('../helpers/weak_cache');
const {
  InvalidRequest, UnsupportedGrantType, UnauthorizedClient,
} = require('../helpers/errors');
const noCache = require('../shared/no_cache');
const authAndParams = require('../shared/token_auth');
const bodyParser = require('../shared/selective_body');
const rejectDupes = require('../shared/reject_dupes');

module.exports = function tokenAction(provider) {
  const parseBody = bodyParser('application/x-www-form-urlencoded');
  return [
    noCache,
    parseBody,
    ...authAndParams(provider, instance(provider).grantTypeWhitelist, 'token'),

    rejectDupes.only('grant_type'),
    async function supportedGrantTypeCheck(ctx, next) {
      presence(ctx, 'grant_type');

      const supported = instance(provider).configuration('grantTypes');

      if (!supported.has(ctx.oidc.params.grant_type)) {
        throw new UnsupportedGrantType();
      }

      await next();
    },

    async function allowedGrantTypeCheck(ctx, next) {
      if (!ctx.oidc.client.grantTypeAllowed(ctx.oidc.params.grant_type)) {
        throw new UnauthorizedClient('requested grant type is restricted to this client');
      }

      await next();
    },

    async function implicitCheck(ctx, next) {
      if (ctx.oidc.params.grant_type === 'implicit') {
        throw new InvalidRequest('implicit is not a grant resolved with a token endpoint call');
      }

      await next();
    },

    async function rejectDupesOptionalExcept(ctx, next) {
      const { grantTypeDupes } = instance(provider);
      const grantType = ctx.oidc.params.grant_type;
      if (grantTypeDupes.has(grantType)) {
        return rejectDupes.except(ctx, next, ...grantTypeDupes.get(grantType));
      }
      return rejectDupes(ctx, next);
    },

    async function callTokenHandler(ctx, next) {
      debug('accepted uuid=%s %o', ctx.oidc.uuid, ctx.oidc.params);
      const grantType = ctx.oidc.params.grant_type;

      const { grantTypeHandlers } = instance(provider);

      await grantTypeHandlers.get(grantType)(ctx, next);
      provider.emit('grant.success', ctx);
      debug('response uuid=%s %o', ctx.oidc.uuid, ctx.body);
    },
  ];
};
