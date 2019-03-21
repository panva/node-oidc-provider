const debug = require('debug')('oidc-provider:authentication:resumed');

const resumeRoutes = new Set(['resume', 'device_resume']);

module.exports = function authorizationEmit(ctx, next) {
  if (resumeRoutes.has(ctx.oidc.route)) {
    debug('uid=%s %o', ctx.oidc.uid, ctx.oidc.result);
    ctx.oidc.provider.emit('interaction.ended', ctx);
  }

  return next();
};
