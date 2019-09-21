const debug = require('debug')('oidc-provider:pushed_authorization_request:success');

const { PUSHED_REQUEST_URN } = require('../../consts');
const epochTime = require('../../helpers/epoch_time');
const JWT = require('../../helpers/jwt');

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

    if (!ttl) {
      ttl = 300;
    }
  } else {
    ttl = 300;
    request = await JWT.sign(ctx.oidc.params, undefined, 'none', {
      issuer: ctx.oidc.client.clientId,
      audience: ctx.oidc.issuer,
      expiresIn: 300,
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
  debug('request object saved client_id=%s request_uri=%s', ctx.oidc.client.clientId, ctx.body.request_uri);

  return next();
};
