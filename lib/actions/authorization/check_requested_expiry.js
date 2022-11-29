import { InvalidRequest } from '../../helpers/errors.js';

/*
 * Validates the requested_expiry parameter
 *
 * @throws: invalid_request
 */
export default function checkRequestedExpiry(ctx, next) {
  if (ctx.oidc.params.requested_expiry !== undefined) {
    const requestedExpiry = +ctx.oidc.params.requested_expiry;

    if (!Number.isSafeInteger(requestedExpiry) || Math.sign(requestedExpiry) !== 1) {
      throw new InvalidRequest('invalid requested_expiry parameter value');
    }
  }

  return next();
}
