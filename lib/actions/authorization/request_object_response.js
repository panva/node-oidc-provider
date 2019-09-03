const debug = require('debug')('oidc-provider:request_object:success');

const { PUSHED_REQUEST_URN } = require('../../consts');
const epochTime = require('../../helpers/epoch_time');
const JWT = require('../../helpers/jwt');

/*
 * Remaps the Request Object Endpoint errors thrown in downstream middlewares
 *
 * @throws: invalid_request_object
 */
module.exports = async function requestObjectResponse(ctx, next) {
  const { request } = ctx.oidc.body;
  const now = epochTime();
  const { payload: { exp } } = JWT.decode(request);
  let ttl = exp - now;

  if (!ttl) {
    ttl = 300;
  }

  const requestObject = new ctx.oidc.provider.RequestObject({ request });

  const id = await requestObject.save(ttl);

  ctx.oidc.entity('RequestObject', requestObject);

  ctx.status = 201;
  ctx.body = {
    expires_in: ttl,
    request_uri: `${PUSHED_REQUEST_URN}${id}`,
  };

  ctx.oidc.provider.emit('request_object.success', ctx, ctx.oidc.client);
  debug('request object saved client_id=%s request_uri=%s', ctx.body.aud, ctx.body.request_uri);

  return next();
};
