const { intersection } = require('lodash');
const instance = require('../../helpers/weak_cache');

module.exports.handler = function getClientCredentialsHandler(provider) {
  return async function clientCredentialsResponse(ctx, next) {
    const { ClientCredentials } = provider;
    const scope = intersection(
      String(ctx.oidc.params.scope).split(' '),
      instance(provider).configuration('scopes'),
    );

    const token = new ClientCredentials({
      clientId: ctx.oidc.client.clientId,
      scope: scope.length ? scope.join(' ') : undefined,
    });

    const value = await token.save();
    ctx.oidc.entity('ClientCredentials', token);

    ctx.body = {
      access_token: value,
      expires_in: token.expiration,
      token_type: 'Bearer',
    };

    await next();
  };
};

module.exports.parameters = ['scope'];
