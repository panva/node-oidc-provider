const {
  InvalidRequestError,
  RegistrationNotSupportedError,
  RequestNotSupportedError,
  RequestUriNotSupportedError,
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
    ctx.throw(new RequestNotSupportedError());
  }

  if (!feature.requestUri && params.request_uri !== undefined) {
    ctx.throw(new RequestUriNotSupportedError());
  }

  if (params.registration !== undefined) {
    ctx.throw(new RegistrationNotSupportedError());
  }

  ctx.assert(
    params.request === undefined || params.request_uri === undefined,
    new InvalidRequestError('request and request_uri parameters MUST NOT be used together'),
  );

  await next();
};
