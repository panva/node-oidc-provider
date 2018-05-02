const { intersection } = require('lodash');
const instance = require('../../helpers/weak_cache');

module.exports.handler = function getClientCredentialsHandler(provider) {
  return async function clientCredentialsResponse(ctx, next) {
    const { ClientCredentials } = provider;
    const { audiences, scopes } = instance(provider).configuration();
    const scope = intersection(String(ctx.oidc.params.scope).split(' '), scopes).join(' ');

    const token = new ClientCredentials({
      clientId: ctx.oidc.client.clientId,
      scope: scope || undefined,
    });

    token.setAudiences(await audiences(ctx, undefined, token, 'client_credentials', scope));

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
