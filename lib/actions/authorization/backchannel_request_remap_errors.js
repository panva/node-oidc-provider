import { InvalidRequestObject } from '../../helpers/errors.js';

/*
 * Remaps the Backchannel Authentication Endpoint errors thrown in downstream middlewares.
 *
 * @throws: invalid_request
 */
export default async function requestObjectRemapErrors(ctx, next) {
  return next().catch((err) => {
    if (err instanceof InvalidRequestObject) {
      Object.assign(err, {
        message: 'invalid_request',
        error: 'invalid_request',
      });
    }

    throw err;
  });
}
