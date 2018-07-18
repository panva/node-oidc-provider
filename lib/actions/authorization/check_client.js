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
module.exports = ({ Client }) => async function checkClient(ctx, next) {
  presence(ctx, 'client_id');

  const client = await Client.find(ctx.oidc.params.client_id);

  if (!client) {
    throw new InvalidClient();
  }

  ctx.oidc.entity('Client', client);

  await next();
};
