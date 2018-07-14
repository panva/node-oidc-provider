const Debug = require('debug');

const accepted = new Debug('oidc-provider:authentication:accepted');
const resumed = new Debug('oidc-provider:authentication:resumed');

const authorizationRoutes = new Set(['authorization', 'code_verification']);

module.exports = provider => async function authorizationEmit(ctx, next) {
  if (authorizationRoutes.has(ctx.oidc.route)) {
    accepted('uuid=%s %o', ctx.oidc.uuid, ctx.oidc.params);
    provider.emit('authorization.accepted', ctx);
  } else {
    resumed('uuid=%s %o', ctx.oidc.uuid, ctx.oidc.result);
    provider.emit('interaction.ended', ctx);
  }
  await next();
};
