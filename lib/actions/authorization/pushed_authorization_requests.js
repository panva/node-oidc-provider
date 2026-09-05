import { UnsecuredJWT } from 'jose';

import { InvalidRequestUri, RequestUriNotSupported, InvalidRedirectUri, InvalidRequest } from '../../helpers/errors.js';
import instance from '../../helpers/weak_cache.js';
import { PUSHED_REQUEST_URN } from '../../consts/index.js';
import epochTime from '../../helpers/epoch_time.js';
import * as JWT from '../../helpers/jwt.js';

/*
 * Validates request_uri is a PAR one when PAR is enabled and loads it. Throws
 */
export async function loadPushedAuthorizationRequest(ctx, next) {
  const { pushedAuthorizationRequests } = instance(ctx.oidc.provider).features;
  const { params, provider: { PushedAuthorizationRequest } } = ctx.oidc;

  rejectRequestAndUri(ctx, () => {});

  if (params.request_uri !== undefined) {
    if (pushedAuthorizationRequests.enabled && params.request_uri.startsWith(PUSHED_REQUEST_URN)) {
      if (!URL.canParse(params.request_uri)) {
        throw new InvalidRequestUri('invalid request_uri');
      }
      const [, id] = params.request_uri.split(PUSHED_REQUEST_URN);
      const pushedAuthorizationRequest = await PushedAuthorizationRequest.find(id, {
        ignoreExpiration: true,
      });
      if (!pushedAuthorizationRequest?.isValid) {
        throw new InvalidRequestUri('request_uri is invalid, expired, or was already used');
      }
      ctx.oidc.entity('PushedAuthorizationRequest', pushedAuthorizationRequest);
      params.request = pushedAuthorizationRequest.request;
    } else {
      throw new RequestUriNotSupported();
    }
  }

  return next();
}

/*
 * Remaps the Pushed Authorization Request Endpoint errors thrown in downstream middlewares.
 */
async function requestObjectRemapErrors(_ctx, next) {
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

const MAX_TTL = 60;

export async function pushedAuthorizationRequestResponse(ctx) {
  let request;
  let ttl;
  let dpopJkt;
  const now = epochTime();
  if (ctx.oidc.body.request) {
    ({ request } = ctx.oidc.body);
    const { payload: { exp, dpop_jkt: thumbprint } } = JWT.decode(request);
    ttl = exp - now;

    if (!Number.isInteger(ttl) || ttl > MAX_TTL) {
      ttl = MAX_TTL;
    }
    dpopJkt = thumbprint || ctx.oidc.params.dpop_jkt;
  } else {
    ttl = MAX_TTL;
    const payload = { ...ctx.oidc.params };

    if (payload.claims) {
      payload.claims = JSON.parse(payload.claims);
    }

    if (payload.authorization_details) {
      payload.authorization_details = JSON.parse(payload.authorization_details);
    }

    request = new UnsecuredJWT(payload)
      .setIssuedAt(now)
      .setIssuer(ctx.oidc.client.clientId)
      .setAudience(ctx.oidc.issuer)
      .setExpirationTime(now + MAX_TTL)
      .setNotBefore(now)
      .encode();
    dpopJkt = ctx.oidc.params.dpop_jkt;
  }

  const requestObject = new ctx.oidc.provider.PushedAuthorizationRequest({
    request,
    dpopJkt,
    trusted: ctx.oidc.client.clientAuthMethod !== 'none' || !!ctx.oidc.trusted?.length,
  });

  if (ctx.oidc.client.clientAuthMethod === 'attest_jwt_client_auth') {
    await requestObject.setAttestBinding(ctx);
  }

  const id = await requestObject.save(ttl);

  ctx.oidc.entity('PushedAuthorizationRequest', requestObject);

  ctx.status = 201;
  ctx.body = {
    expires_in: ttl,
    request_uri: `${PUSHED_REQUEST_URN}${id}`,
  };
  ctx.oidc.provider.emit('pushed_authorization_request.success', ctx, ctx.oidc.client);
}

/*
 * Rejects when request and request_uri are used together.
 */
export function rejectRequestAndUri(ctx, next) {
  if (ctx.oidc.params.request !== undefined && ctx.oidc.params.request_uri !== undefined) {
    throw new InvalidRequest('request and request_uri parameters MUST NOT be used together');
  }

  return next();
}

export { requestObjectRemapErrors as pushedAuthorizationRequestRemapErrors };
