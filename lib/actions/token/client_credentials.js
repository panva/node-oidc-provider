module.exports.handler = function getClientCredentialsHandler(provider) {
  return async function clientCredentialsResponse(ctx, next) {
    const ClientCredentials = provider.ClientCredentials;
    const at = new ClientCredentials({
      clientId: ctx.oidc.client.clientId,
      scope: ctx.oidc.params.scope,
    });

    const token = await at.save();
    const tokenType = 'Bearer';
    const expiresIn = ClientCredentials.expiresIn;

    ctx.body = { access_token: token, expires_in: expiresIn, token_type: tokenType };

    await next();
  };
};

module.exports.parameters = ['scope'];
