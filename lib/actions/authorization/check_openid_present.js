const { InvalidRequestError } = require('../../helpers/errors');

/*
 * Checks openid presence amongst the requested scopes
 *
 * @throws: invalid_request
 */
module.exports = async function checkOpenIdPresent(ctx, next) {
  const scopes = ctx.oidc.params.scope.split(' ');
  ctx.assert(scopes.includes('openid'), new InvalidRequestError('openid is required scope'));
  await next();
};
