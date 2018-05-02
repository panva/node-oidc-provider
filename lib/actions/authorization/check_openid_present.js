const { InvalidRequest } = require('../../helpers/errors');

/*
 * Checks openid presence amongst the requested scopes
 *
 * @throws: invalid_request
 */
module.exports = async function checkOpenIdPresent(ctx, next) {
  const scopes = ctx.oidc.params.scope.split(' ');
  if (!scopes.includes('openid')) {
    ctx.throw(new InvalidRequest('openid is required scope'));
  }
  await next();
};
