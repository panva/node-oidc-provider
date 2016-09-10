'use strict';

const errors = require('../../helpers/errors');

/*
 * Checks client_id
 * - value presence in provided params
 * - value being resolved as a client
 *
 * @throws: invalid_request
 * @throws: invalid_client
 */
module.exports = provider => function* checkClient(next) {
  const clientId = this.oidc.params.client_id;
  this.assert(clientId, new errors.InvalidRequestError('missing required parameter client_id'));

  const Client = provider.Client;
  const client = yield Client.find(String(clientId));

  this.assert(client, new errors.InvalidClientError());

  this.oidc.client = client;

  yield next;
};
