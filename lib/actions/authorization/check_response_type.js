const instance = require('../../helpers/weak_cache');
const {
  UnsupportedResponseType,
  RestrictedResponseType,
} = require('../../helpers/errors');

/*
 * Validates requested response_type is supported by the provided and whitelisted in the client
 * configuration
 *
 * @throws: unsupported_response_type
 * @throws: restricted_response_type
 */
module.exports = provider => async function checkResponseType(ctx, next) {
  const { params } = ctx.oidc;
  const supported = instance(provider).configuration('responseTypes');

  if (!supported.includes(params.response_type)) {
    ctx.throw(new UnsupportedResponseType());
  }

  if (!ctx.oidc.client.responseTypeAllowed(params.response_type)) {
    ctx.throw(new RestrictedResponseType());
  }

  await next();
};
