const instance = require('../helpers/weak_cache');

module.exports = function renderJWKS(ctx, next) {
  ctx.body = instance(ctx.oidc.provider).jwksResponse;
  ctx.type = 'application/jwk-set+json; charset=utf-8';

  return next();
};
