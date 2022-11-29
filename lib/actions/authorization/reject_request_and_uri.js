import { InvalidRequest } from '../../helpers/errors.js';

/*
 * Rejects when request and request_uri are used together.
 *
 * @throws: invalid_request
 */
export default function rejectRequestAndUri(ctx, next) {
  if (ctx.oidc.params.request !== undefined && ctx.oidc.params.request_uri !== undefined) {
    throw new InvalidRequest('request and request_uri parameters MUST NOT be used together');
  }

  return next();
}
