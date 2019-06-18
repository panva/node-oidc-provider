const { RegistrationNotSupported } = require('../../helpers/errors');

/*
 * Rejects registration parameter as not supported.
 *
 * @throws: registration_not_supported
 */
module.exports = function rejectRegistration(ctx, next) {
  if (ctx.oidc.params.registration !== undefined) {
    throw new RegistrationNotSupported();
  }

  return next();
};
