const { UnsecuredJWT } = require('jose');

const { PUSHED_REQUEST_URN } = require('../../consts');
const epochTime = require('../../helpers/epoch_time');
const JWT = require('../../helpers/jwt');

const MAX_TTL = 60;

module.exports = async function pushedAuthorizationRequestResponse(ctx, next) {
  let request;
  let ttl;
  const now = epochTime();
  if (ctx.oidc.body.request) {
    ({ request } = ctx.oidc.body);
    const { payload: { exp } } = JWT.decode(request);
    ttl = exp - now;

    if (!Number.isInteger(ttl) || ttl > MAX_TTL) {
      ttl = MAX_TTL;
    }
  } else {
    ttl = MAX_TTL;
    request = new UnsecuredJWT({ ...ctx.oidc.params })
      .setIssuedAt(now)
      .setIssuer(ctx.oidc.client.clientId)
      .setAudience(ctx.oidc.issuer)
      .setExpirationTime(now + MAX_TTL)
      .setNotBefore(now)
      .encode();
  }

  const requestObject = new ctx.oidc.provider.PushedAuthorizationRequest({ request });

  const id = await requestObject.save(ttl);

  ctx.oidc.entity('PushedAuthorizationRequest', requestObject);

  ctx.status = 201;
  ctx.body = {
    expires_in: ttl,
    request_uri: `${PUSHED_REQUEST_URN}${id}`,
  };

  ctx.oidc.provider.emit('pushed_authorization_request.success', ctx, ctx.oidc.client);

  return next();
};
