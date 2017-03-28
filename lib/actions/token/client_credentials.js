module.exports.handler = function getClientCredentialsHandler({ ClientCredentials }) {
  return async function clientCredentialsResponse(ctx, next) {
    const at = new ClientCredentials({
      clientId: ctx.oidc.client.clientId,
      scope: ctx.oidc.params.scope,
    });

    const token = await at.save();
    const { expiresIn } = ClientCredentials;

    ctx.body = { access_token: token, expires_in: expiresIn, token_type: 'Bearer' };

    await next();
  };
};

module.exports.parameters = ['scope'];
