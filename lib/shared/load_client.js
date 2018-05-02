const { InvalidClientAuth } = require('../helpers/errors');

module.exports = function getLoadClient(provider) {
  return async function loadClient(ctx, next) {
    const client = await provider.Client.find(ctx.oidc.authorization.clientId);

    if (!client) {
      ctx.throw(new InvalidClientAuth('invalid client authentication provided (client not found)'));
    }

    ctx.oidc.entity('Client', client);

    await next();
  };
};
