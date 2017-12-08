'use strict';

module.exports.handler = function getClientCredentialsHandler(provider) {
  return function* clientCredentialsResponse(next) {
    const ClientCredentials = provider.ClientCredentials;
    const at = new ClientCredentials({
      clientId: this.oidc.client.clientId,
      scope: this.oidc.params.scope,
    });

    const token = yield at.save();
    const tokenType = 'Bearer';
    const expiresIn = ClientCredentials.expiresIn;

    this.body = { access_token: token, expires_in: expiresIn, token_type: tokenType };

    yield next;
  };
};

module.exports.parameters = ['scope'];
