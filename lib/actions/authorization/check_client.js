const { InvalidRequestError, InvalidClientError } = require('../../helpers/errors');

/*
 * Checks client_id
 * - value presence in provided params
 * - value being resolved as a client
 *
 * @throws: invalid_request
 * @throws: invalid_client
 */
module.exports = ({ Client }) => async function checkClient(ctx, next) {
  const { client_id } = ctx.oidc.params;
  ctx.assert(client_id, new InvalidRequestError('missing required parameter client_id'));

  const client = await Client.find(String(client_id));

  ctx.assert(client, new InvalidClientError());

  ctx.oidc.client = client;

  await next();
};
