const { intersection } = require('lodash');
const instance = require('../../helpers/weak_cache');

module.exports.handler = function getClientCredentialsHandler(provider) {
  return async function clientCredentialsResponse(ctx, next) {
    const { ClientCredentials } = provider;
    const scope = intersection(
      String(ctx.oidc.params.scope).split(' '),
      instance(provider).configuration('scopes'),
    );

    const at = new ClientCredentials({
      clientId: ctx.oidc.client.clientId,
      scope: scope.length ? scope.join(' ') : undefined,
    });

    const token = await at.save();

    ctx.body = {
      access_token: token,
      expires_in: at.expiration,
      token_type: 'Bearer',
    };

    await next();
  };
};

module.exports.parameters = ['scope'];
