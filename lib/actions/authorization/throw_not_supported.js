const {
  InvalidRequest,
  RegistrationNotSupported,
  RequestNotSupported,
  RequestUriNotSupported,
} = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');

/*
 * Validates parameters that rely features that are not supported by the provider configuration
 * are not provided and that request and request_uri are not used in conjunction.
 *
 * @throws: invalid_request
 * @throws: request_not_supported
 * @throws: request_uri_not_supported
 * @throws: registration_not_supported
 */
module.exports = provider => async function throwNotSupported(ctx, next) {
  const { params } = ctx.oidc;
  const feature = instance(provider).configuration('features');

  if (!feature.request && params.request !== undefined) {
    throw new RequestNotSupported();
  }

  if (!feature.requestUri && params.request_uri !== undefined) {
    throw new RequestUriNotSupported();
  }

  if (params.registration !== undefined) {
    throw new RegistrationNotSupported();
  }

  if (params.request !== undefined && params.request_uri !== undefined) {
    throw new InvalidRequest('request and request_uri parameters MUST NOT be used together');
  }

  await next();
};
