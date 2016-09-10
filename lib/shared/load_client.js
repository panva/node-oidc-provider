'use strict';

const errors = require('../helpers/errors');

module.exports = function getLoadClient(provider) {
  return function* loadClient(next) {
    const client = yield provider.Client.find(this.oidc.authorization.clientId);

    this.assert(client, new errors.InvalidClientError(
      'invalid client authentication provided (client not found)'));

    this.oidc.client = client;

    yield next;
  };
};
