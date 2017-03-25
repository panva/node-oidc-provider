const Debug = require('debug');

const accepted = new Debug('oidc-provider:authentication:accepted');
const resumed = new Debug('oidc-provider:authentication:resumed');

module.exports = provider => async function authorizationEmit(ctx, next) {
  if (ctx.oidc.result) {
    resumed('uuid=%s %o', ctx.oidc.uuid, ctx.oidc.result);
    provider.emit('interaction.ended', ctx);
  } else {
    accepted('uuid=%s %o', ctx.oidc.uuid, ctx.oidc.params);
    provider.emit('authorization.accepted', ctx);
  }
  await next();
};
