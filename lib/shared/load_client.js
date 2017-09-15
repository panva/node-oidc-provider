const { InvalidClientError } = require('../helpers/errors');

module.exports = function getLoadClient(provider) {
  return async function loadClient(ctx, next) {
    const client = await provider.Client.find(ctx.oidc.authorization.clientId);

    if (!client) {
      ctx.throw(new InvalidClientError('invalid client authentication provided (client not found)'));
    }

    ctx.oidc.client = client;

    await next();
  };
};
