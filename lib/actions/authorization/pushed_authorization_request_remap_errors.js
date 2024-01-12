import { InvalidRedirectUri } from '../../helpers/errors.js';

/*
 * Remaps the Pushed Authorization Request Endpoint errors thrown in downstream middlewares.
 */
export default async function requestObjectRemapErrors(ctx, next) {
  return next().catch((err) => {
    if (err instanceof InvalidRedirectUri) {
      Object.assign(err, {
        message: 'invalid_request',
        error: 'invalid_request',
      });
    }

    throw err;
  });
}
