const { PUSHED_REQUEST_URN } = require('../../consts');
const epochTime = require('../../helpers/epoch_time');
const JWT = require('../../helpers/jwt');

const MAX_TTL = 60;

/*
 * Remaps the Pushed Authorization Request Endpoint errors thrown in downstream middlewares
 *
 * @throws: invalid_request_object
 */
module.exports = async function pushedAuthorizationRequestResponse(ctx, next) {
  let request;
  let ttl;
  if (ctx.oidc.body.request) {
    ({ request } = ctx.oidc.body);
    const now = epochTime();
    const { payload: { exp } } = JWT.decode(request);
    ttl = exp - now;

    if (!Number.isInteger(ttl) || ttl > MAX_TTL) {
      ttl = MAX_TTL;
    }
  } else {
    ttl = MAX_TTL;
    request = await JWT.sign(ctx.oidc.params, undefined, 'none', {
      issuer: ctx.oidc.client.clientId,
      audience: ctx.oidc.issuer,
      expiresIn: MAX_TTL,
    });
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
