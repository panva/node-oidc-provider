const instance = require('../helpers/weak_cache');

module.exports = function renderCertificates(ctx, next) {
  ctx.body = instance(ctx.oidc.provider).keystore.toJWKS();

  return next();
};
