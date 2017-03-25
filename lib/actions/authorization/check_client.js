const { InvalidRequestError, InvalidClientError } = require('../../helpers/errors');

/*
 * Checks client_id
 * - value presence in provided params
 * - value being resolved as a client
 *
 * @throws: invalid_request
 * @throws: invalid_client
 */
module.exports = provider => async function checkClient(ctx, next) {
  const clientId = ctx.oidc.params.client_id;
  ctx.assert(clientId, new InvalidRequestError('missing required parameter client_id'));

  const Client = provider.Client;
  const client = await Client.find(String(clientId));

  ctx.assert(client, new InvalidClientError());

  ctx.oidc.client = client;

  await next();
};
