import instance from '../../helpers/weak_cache.js';

/*
 * Executes registered extraParams validators.
 */
export default async function checkExtraParams(ctx, next) {
  const { extraParamsValidations } = instance(ctx.oidc.provider).configuration;

  if (!extraParamsValidations) {
    return next();
  }

  for (const [param, validator] of extraParamsValidations) {
    await validator(ctx, ctx.oidc.params[param], ctx.oidc.client);
  }

  return next();
}
