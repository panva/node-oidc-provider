const Params = require('../helpers/params');

module.exports = function assembleParams(whitelist, ctx, next) {
  const params = ctx.method === 'POST' ? ctx.oidc.body : ctx.query;
  ctx.oidc.params = new (Params(whitelist))(params);
  return next();
};
