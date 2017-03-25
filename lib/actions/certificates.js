const instance = require('../helpers/weak_cache');

module.exports = function certificatesAction(provider) {
  return async function renderCertificates(ctx, next) {
    ctx.body = instance(provider).keystore.toJSON();

    await next();
  };
};
