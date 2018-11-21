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
module.exports = provider => async function checkResponseType(ctx, next) {
  const { params } = ctx.oidc;
  const supported = instance(provider).configuration('responseTypes');

  params.response_type = Array.from(new Set(params.response_type.split(' '))).sort().join(' ');

  if (!supported.includes(params.response_type)) {
    throw new UnsupportedResponseType();
  }

  if (!ctx.oidc.client.responseTypeAllowed(params.response_type)) {
    throw new UnauthorizedClient('response_type not allowed for this client');
  }

  await next();
};
