/*
 * assign max_age and acr_values if it is not provided explictly but is configured with default
 * values on the client
 */
module.exports = function assignDefaults(ctx, next) {
  const { params, client } = ctx.oidc;

  if (!params.acr_values && client.defaultAcrValues) {
    params.acr_values = client.defaultAcrValues.join(' ');
  }

  if (params.max_age === undefined && client.defaultMaxAge) {
    params.max_age = client.defaultMaxAge;
  }

  return next();
};
