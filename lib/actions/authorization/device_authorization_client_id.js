module.exports = function deviceAuthorizationResponse(ctx, next) {
  if (!ctx.oidc.body.client_id) {
    ctx.oidc.body.client_id = ctx.oidc.client.clientId;
  }
  return next();
};
