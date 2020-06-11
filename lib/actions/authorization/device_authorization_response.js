const debug = require('debug')('oidc-provider:device_authorization');

const { generate, normalize } = require('../../helpers/user_codes');
const instance = require('../../helpers/weak_cache');

module.exports = async function deviceAuthorizationResponse(ctx, next) {
  const { charset, mask, deviceInfo } = instance(ctx.oidc.provider).configuration('features.deviceFlow');
  const userCode = generate(charset, mask);

  const dc = new ctx.oidc.provider.DeviceCode({
    client: ctx.oidc.client,
    deviceInfo: deviceInfo(ctx),
    grantId: ctx.oidc.uid,
    params: ctx.oidc.params.toPlainObject(),
    userCode: normalize(userCode),
  });

  ctx.oidc.entity('DeviceCode', dc);
  ctx.body = {
    device_code: await dc.save(),
    user_code: userCode,
    verification_uri: ctx.oidc.urlFor('code_verification'),
    verification_uri_complete: ctx.oidc.urlFor('code_verification', {
      query: { user_code: userCode },
    }),
    expires_in: dc.expiration,
  };

  await next();

  ctx.oidc.provider.emit('device_authorization.success', ctx, ctx.body);
  debug('response uid=%s %o', ctx.oidc.uid, ctx.body);
};
