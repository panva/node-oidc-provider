'use strict';

/*
 * assign max_age and acr_values if it is not provided explictly but is configured with default
 * values on the client
 */
module.exports = async function assignDefaults(ctx, next) {
  const params = ctx.oidc.params;
  const client = ctx.oidc.client;

  if (!params.acr_values && client.defaultAcrValues) {
    params.acr_values = client.defaultAcrValues.join(' ');
  }

  if (!params.max_age && client.defaultMaxAge) {
    params.max_age = client.defaultMaxAge;
  }

  await next();
};
