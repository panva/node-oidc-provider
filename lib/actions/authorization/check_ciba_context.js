const instance = require('../../helpers/weak_cache');

module.exports = async function checkCibaContext(ctx, next) {
  const { features: { ciba } } = instance(ctx.oidc.provider).configuration();

  await Promise.all([
    ciba.validateRequestContext(ctx, ctx.oidc.params.request_context),
    ciba.validateBindingMessage(ctx, ctx.oidc.params.binding_message),
  ]);

  return next();
};
