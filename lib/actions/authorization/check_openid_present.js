'use strict';

const errors = require('../../helpers/errors');

/*
 * Checks openid presence amongst the requested scopes
 *
 * @throws: invalid_request
 */
module.exports = async function checkOpenIdPresent(ctx, next) {
  const scopes = ctx.oidc.params.scope.split(' ');

  ctx.assert(scopes.indexOf('openid') !== -1,
    new errors.InvalidRequestError('openid is required scope'));

  await next();
};
