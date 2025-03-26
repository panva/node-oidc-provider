import instance from '../helpers/weak_cache.js';

export default function renderJWKS(ctx, next) {
  const { keys } = instance(ctx.oidc.provider).jwks;
  ctx.body = { keys };
  ctx.type = 'application/jwk-set+json; charset=utf-8';

  return next();
}
