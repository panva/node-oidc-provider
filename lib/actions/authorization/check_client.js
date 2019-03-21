const { InvalidClient } = require('../../helpers/errors');
const presence = require('../../helpers/validate_presence');

/*
 * Checks client_id
 * - value presence in provided params
 * - value being resolved as a client
 *
 * @throws: invalid_request
 * @throws: invalid_client
 */
module.exports = async function checkClient(ctx, next) {
  presence(ctx, 'client_id');

  const client = await ctx.oidc.provider.Client.find(ctx.oidc.params.client_id);

  if (!client) {
    // there's no point in checking again in authorization error handler
    ctx.oidc.noclient = true;
    throw new InvalidClient();
  }

  ctx.oidc.entity('Client', client);

  return next();
};
