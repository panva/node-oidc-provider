const Params = require('../helpers/params');

module.exports = function assembleParams(allowList, ctx, next) {
  const params = ctx.method === 'POST' ? ctx.oidc.body : ctx.query;
  ctx.oidc.params = new (Params(allowList))(params);
  return next();
};
