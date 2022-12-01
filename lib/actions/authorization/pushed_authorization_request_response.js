import { UnsecuredJWT } from 'jose';

import { PUSHED_REQUEST_URN } from '../../consts/index.js';
import epochTime from '../../helpers/epoch_time.js';
import * as JWT from '../../helpers/jwt.js';

const MAX_TTL = 60;

export default async function pushedAuthorizationRequestResponse(ctx, next) {
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
    request = new UnsecuredJWT({ ...ctx.oidc.params })
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

  const id = await requestObject.save(ttl);

  ctx.oidc.entity('PushedAuthorizationRequest', requestObject);

  ctx.status = 201;
  ctx.body = {
    expires_in: ttl,
    request_uri: `${PUSHED_REQUEST_URN}${id}`,
  };

  ctx.oidc.provider.emit('pushed_authorization_request.success', ctx, ctx.oidc.client);

  return next();
}
