const debug = require('debug')('oidc-provider:device_authorization');

const { generate, normalize } = require('../../helpers/user_codes');
const instance = require('../../helpers/weak_cache');

module.exports = function getDeviceAuthorizationResponse(provider) {
  const { DeviceCode } = provider;
  const {
    pkce, deviceFlow: { charset, mask, deviceInfo },
  } = instance(provider).configuration('features');

  return async function deviceAuthorizationResponse(ctx, next) {
    const userCode = generate(charset, mask);

    const dc = new DeviceCode({
      client: ctx.oidc.client,
      grantId: ctx.oidc.uuid,
      params: ctx.oidc.params.toPlainObject(),
      userCode: normalize(userCode),
      deviceInfo: deviceInfo(ctx),
    });

    if (pkce) {
      dc.codeChallenge = ctx.oidc.params.code_challenge;
      dc.codeChallengeMethod = ctx.oidc.params.code_challenge_method;
    }

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
    provider.emit('device_authorization.success', ctx);
    debug('response uuid=%s %o', ctx.oidc.uuid, ctx.body);
  };
};
