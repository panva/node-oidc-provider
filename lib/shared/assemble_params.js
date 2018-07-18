const getParams = require('../helpers/params');

module.exports = function getAssembleParams(whitelist) {
  const Params = getParams(whitelist);

  return async function assembleParams(ctx, next) {
    const params = ctx.method === 'POST' ? ctx.oidc.body : ctx.query;
    ctx.oidc.params = new Params(params);
    await next();
  };
};
