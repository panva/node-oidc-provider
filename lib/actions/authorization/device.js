import Params from '../../helpers/params.js';
import { NotFoundError, ExpiredError, AlreadyUsedError, ReRenderError, AbortedError } from '../../helpers/re_render_errors.js';
import { AccessDenied } from '../../helpers/errors.js';
import errOut from '../../helpers/err_out.js';
import combinedScope from '../../helpers/combined_scope.js';
import { boolean } from '../../helpers/configuration_result.js';
import normalizeAuthorizationDetails from '../../helpers/normalize_authorization_details.js';
import instance from '../../helpers/weak_cache.js';
import { generate, normalize } from '../../helpers/user_codes.js';
import { getAuthorizationParams } from './request_parameters.js';

export async function deviceUserFlow(ctx, next) {
  if (ctx.oidc.route === 'device_resume') {
    const code = await ctx.oidc.provider.DeviceCode.find(
      ctx.oidc.entities.Interaction.deviceCode,
      { ignoreExpiration: true, ignoreSessionBinding: true },
    );

    if (!code) {
      throw new NotFoundError();
    }

    if (code.isExpired) {
      throw new ExpiredError();
    }

    if (code.error || code.accountId) {
      throw new AlreadyUsedError();
    }

    ctx.oidc.entity('DeviceCode', code);
  } else {
    ctx.oidc.params = new Params(getAuthorizationParams(ctx), ctx.oidc.deviceCode.params);
  }

  await next();
}

export async function deviceUserFlowErrors(ctx, next) {
  try {
    await next();
  } catch (cause) {
    if (!(cause instanceof ReRenderError)) {
      const out = errOut(cause);

      let code = ctx.oidc.deviceCode;

      if (!code && ctx.oidc.entities.Interaction?.deviceCode) {
        code = await ctx.oidc.provider.DeviceCode.find(
          ctx.oidc.entities.Interaction.deviceCode,
          { ignoreExpiration: true, ignoreSessionBinding: true },
        );
      }

      if (code) {
        Object.assign(code, {
          error: out.error,
          errorDescription: out.error_description,
        });
        await code.save();
        if (cause instanceof AccessDenied) {
          throw new AbortedError({ cause });
        }
      }
    }

    throw cause;
  }
}

async function deviceVerificationResponse(ctx) {
  const { configuration, features } = instance(ctx.oidc.provider);
  const code = ctx.oidc.deviceCode;

  const scopeSet = combinedScope(
    ctx.oidc.grant,
    ctx.oidc.requestParamScopes,
    ctx.oidc.resourceServers,
  );

  Object.assign(code, {
    accountId: ctx.oidc.session.accountId,
    acr: ctx.oidc.acr,
    amr: ctx.oidc.amr,
    authTime: ctx.oidc.session.authTime(),
    claims: ctx.oidc.claims,
    grantId: ctx.oidc.session.grantIdFor(ctx.oidc.client.clientId),
    scope: [...scopeSet].join(' '),
    sessionUid: ctx.oidc.session.uid,
    resource: Object.keys(ctx.oidc.resourceServers),
  });

  if (Object.keys(code.claims).length === 0) {
    delete code.claims;
  }

  switch (code.resource.length) {
    case 0:
      delete code.resource;
      break;
    case 1:
      [code.resource] = code.resource;
      break;
  }

  if (boolean(await configuration.expiresWithSession(ctx, code), 'expiresWithSession')) {
    code.expiresWithSession = true;
  } else {
    ctx.oidc.session.authorizationFor(ctx.oidc.client.clientId).persistsLogout = true;
  }

  if (ctx.oidc.client.includeSid() || (ctx.oidc.claims.id_token && 'sid' in ctx.oidc.claims.id_token)) {
    code.sid = ctx.oidc.session.sidFor(ctx.oidc.client.clientId);
  }

  if (
    features.richAuthorizationRequests.enabled
    && (
      ctx.oidc.params.authorization_details !== undefined
      || ctx.oidc.grant.rar?.length
    )
  ) {
    code.rar = normalizeAuthorizationDetails(
      await features.richAuthorizationRequests.authorizationDetailsForGrantSource(ctx, code),
    );
  }

  await code.save();

  await features.deviceFlow.successSource(ctx);

  ctx.oidc.provider.emit('authorization.success', ctx);
}

export async function deviceAuthorizationResponse(ctx) {
  const { charset, mask, deviceInfo } = instance(ctx.oidc.provider).features.deviceFlow;
  const userCode = generate(charset, mask);

  const dc = new ctx.oidc.provider.DeviceCode({
    client: ctx.oidc.client,
    deviceInfo: deviceInfo(ctx),
    params: ctx.oidc.params.toPlainObject(),
    userCode: normalize(userCode),
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

export { deviceVerificationResponse as deviceUserFlowResponse };
