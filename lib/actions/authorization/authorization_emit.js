const resumeRoutes = new Set(['resume', 'device_resume']);

module.exports = function authorizationEmit(ctx, next) {
  if (resumeRoutes.has(ctx.oidc.route)) {
    ctx.oidc.provider.emit('interaction.ended', ctx);
  }

  return next();
};
