const { strict: assert } = require('node:assert');

const {
  InvalidClient, InvalidRequestObject,
} = require('../../helpers/errors.js');
const presence = require('../../helpers/validate_presence.js');
const base64url = require('../../helpers/base64url.js');
const instance = require('../../helpers/weak_cache.js');
const { PUSHED_REQUEST_URN } = require('../../consts/index.js');

const rejectRequestAndUri = require('./reject_request_and_uri.js');
const loadPushedAuthorizationRequest = require('./load_pushed_authorization_request.js');

/*
 * Checks client_id
 * - value presence in provided params
 * - value being resolved as a client
 *
 * @throws: invalid_request
 * @throws: invalid_client
 */
module.exports = async function checkClient(ctx, next) {
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
      assert(parts.length === 3 || parts.length === 5);
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
};
