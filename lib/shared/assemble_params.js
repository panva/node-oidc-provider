import Params from '../helpers/params.js';

export default function assembleParams(allowList, ctx, next) {
  const params = ctx.method === 'POST' ? ctx.oidc.body : ctx.query;
  ctx.oidc.params = new (Params(allowList))(params);
  return next();
}
