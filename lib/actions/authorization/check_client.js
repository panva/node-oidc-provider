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
  const { client_id: clientId } = ctx.oidc.params;

  if (!clientId) {
    ctx.throw(new InvalidRequestError('missing required parameter client_id'));
  }

  const client = await Client.find(String(clientId));

  if (!client) {
    ctx.throw(new InvalidClientError());
  }

  ctx.oidc.entity('Client', client);

  await next();
};
