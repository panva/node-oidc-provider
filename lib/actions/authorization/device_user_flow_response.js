import combinedScope from '../../helpers/combined_scope.js';
import { boolean } from '../../helpers/configuration_result.js';
import normalizeAuthorizationDetails from '../../helpers/normalize_authorization_details.js';
import instance from '../../helpers/weak_cache.js';

export default async function deviceVerificationResponse(ctx) {
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
