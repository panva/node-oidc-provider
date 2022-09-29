import presence from '../../helpers/validate_presence.js';
import * as base64url from '../../helpers/base64url.js';
import instance from '../../helpers/weak_cache.js';
import { PUSHED_REQUEST_URN } from '../../consts/index.js';
import {
  InvalidClient, InvalidRequestObject,
} from '../../helpers/errors.js';

import rejectRequestAndUri from './reject_request_and_uri.js';
import loadPushedAuthorizationRequest from './load_pushed_authorization_request.js';

/*
 * Checks client_id
 * - value presence in provided params
 * - value being resolved as a client
 *
 * @throws: invalid_request
 * @throws: invalid_client
 */
export default async function checkClient(ctx, next) {
  const { oidc: { params } } = ctx;
  const { pushedAuthorizationRequests } = instance(ctx.oidc.provider).configuration('features');

  try {
    presence(ctx, 'client_id');
  } catch (err) {
    const { request_uri: requestUri } = params;
    let { request } = params;

    if (
      !(
        pushedAuthorizationRequests.enabled
        && requestUri
        && requestUri.startsWith(PUSHED_REQUEST_URN)
      )
      && request === undefined
    ) {
      throw err;
    }

    rejectRequestAndUri(ctx, () => {});

    if (requestUri) {
      const loadedRequestObject = await loadPushedAuthorizationRequest(ctx);
      ({ request } = loadedRequestObject);
    }

    const parts = request.split('.');
    let decoded;
    let clientId;

    try {
      if (parts.length !== 3 && parts.length !== 5) {
        throw new Error();
      }
      parts.forEach((part, i, { length }) => {
        if (length === 3 && i === 1) { // JWT Payload
          decoded = JSON.parse(base64url.decodeToBuffer(part));
        } else if (length === 5 && i === 0) { // JWE Header
          decoded = JSON.parse(base64url.decodeToBuffer(part));
        }
      });
    } catch (error) {
      throw new InvalidRequestObject(`Request Object is not a valid ${parts.length === 5 ? 'JWE' : 'JWT'}`);
    }

    if (decoded) {
      clientId = decoded.iss;
    }

    if (typeof clientId !== 'string' || !clientId) {
      throw err;
    }

    params.client_id = clientId;
  }

  const client = await ctx.oidc.provider.Client.find(ctx.oidc.params.client_id);

  if (!client) {
    // there's no point in checking again in authorization error handler
    ctx.oidc.noclient = true;
    throw new InvalidClient('client is invalid', 'client not found');
  }

  ctx.oidc.entity('Client', client);

  return next();
}
