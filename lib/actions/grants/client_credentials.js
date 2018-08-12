const instance = require('../../helpers/weak_cache');

module.exports.handler = function getClientCredentialsHandler(provider) {
  return async function clientCredentialsResponse(ctx, next) {
    const { ClientCredentials } = provider;
    const {
      audiences, scopes: statics, dynamicScopes: dynamics,
    } = instance(provider).configuration();

    const scopes = ctx.oidc.params.scope ? ctx.oidc.params.scope.split(' ').filter((scope) => {
      if (statics.includes(scope)) {
        return true;
      }

      for (const dynamic of dynamics) { // eslint-disable-line no-restricted-syntax
        if (dynamic.exec(scope)) {
          return true;
        }
      }

      return false;
    }) : [];

    const token = new ClientCredentials({
      clientId: ctx.oidc.client.clientId,
      scope: scopes.join(' ') || undefined,
    });

    token.setAudiences(await audiences(ctx, undefined, token, 'client_credentials'));

    const value = await token.save();
    ctx.oidc.entity('ClientCredentials', token);

    ctx.body = {
      access_token: value,
      expires_in: token.expiration,
      token_type: 'Bearer',
      scope: token.scope,
    };

    await next();
  };
};

module.exports.parameters = 'scope';
