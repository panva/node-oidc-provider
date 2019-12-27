const instance = require('../../helpers/weak_cache');
const {
  UnsupportedResponseType,
  UnauthorizedClient,
} = require('../../helpers/errors');

/*
 * Validates requested response_type is supported by the provided and whitelisted in the client
 * configuration
 *
 * @throws: unsupported_response_type
 * @throws: unauthorized_client
 */
module.exports = function checkResponseType(ctx, next) {
  const { params } = ctx.oidc;
  const supported = instance(ctx.oidc.provider).configuration('responseTypes');

  params.response_type = [...new Set(params.response_type.split(' '))].sort().join(' ');

  if (!supported.includes(params.response_type)) {
    throw new UnsupportedResponseType();
  }

  if (!ctx.oidc.client.responseTypeAllowed(params.response_type)) {
    throw new UnauthorizedClient('requested response_type is not allowed for this client');
  }

  return next();
};
