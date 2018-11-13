const { get } = require('lodash');
const debug = require('debug')('oidc-provider:authentication:success');

const instance = require('../../helpers/weak_cache');

module.exports = provider => async function deviceVerificationResponse(ctx, next) {
  const {
    deviceFlowSuccess, features: { resourceIndicators },
  } = instance(provider).configuration();
  const code = ctx.oidc.deviceCode;

  Object.assign(code, {
    accountId: ctx.oidc.session.accountId(),
    acr: ctx.oidc.acr,
    amr: ctx.oidc.amr,
    authTime: ctx.oidc.session.authTime(),
    claims: ctx.oidc.resolvedClaims(),
    scope: ctx.oidc.acceptedScope(),
  });

  if (ctx.oidc.client.includeSid() || get(ctx.oidc.claims, 'id_token.sid')) {
    code.sid = ctx.oidc.session.sidFor(ctx.oidc.client.clientId);
  }

  if (resourceIndicators) {
    code.resource = ctx.oidc.params.resource;
  }

  await code.save();

  await deviceFlowSuccess(ctx);

  provider.emit('authorization.success', ctx);
  debug('uuid=%s %o', ctx.oidc.uuid, {});

  await next();
};
