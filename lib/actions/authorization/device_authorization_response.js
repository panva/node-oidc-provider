import { InvalidRequest } from '../../helpers/errors.js';
import { generate, normalize } from '../../helpers/user_codes.js';
import instance from '../../helpers/weak_cache.js';
import dpopValidate, { CHALLENGE_OK_WINDOW } from '../../helpers/validate_dpop.js';
import epochTime from '../../helpers/epoch_time.js';

export default async function deviceAuthorizationResponse(ctx) {
  const { charset, mask, deviceInfo } = instance(ctx.oidc.provider).features.deviceFlow;
  const userCode = generate(charset, mask);

  let dpopJkt;
  const dPoP = await dpopValidate(ctx);
  if (dPoP) {
    if (!dPoP.allowReplay) {
      const { ReplayDetection } = ctx.oidc.provider;
      const unique = await ReplayDetection.unique(
        ctx.oidc.client.clientId,
        dPoP.jti,
        epochTime() + CHALLENGE_OK_WINDOW,
      );

      ctx.assert(unique, new InvalidRequest('DPoP proof JWT Replay detected'));
    }

    dpopJkt = dPoP.thumbprint;
  }

  const dc = new ctx.oidc.provider.DeviceCode({
    client: ctx.oidc.client,
    deviceInfo: deviceInfo(ctx),
    params: ctx.oidc.params.toPlainObject(),
    userCode: normalize(userCode),
    dpopJkt,
  });

  if (ctx.oidc.client.clientAuthMethod === 'attest_jwt_client_auth') {
    await dc.setAttestBinding(ctx);
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

  ctx.oidc.provider.emit('device_authorization.success', ctx, ctx.body);
}
