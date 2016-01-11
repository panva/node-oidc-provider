'use strict';

let errors = require('../helpers/errors');

module.exports = function (provider) {
  return function * loadClient(next) {
    let client = provider.Client.find(this.oidc.authorization.clientId);

    this.assert(client,
      new errors.InvalidClientError(
        'invalid client authentication provided (client not found)'));

    this.oidc.client = client;

    yield next;
  };
};
