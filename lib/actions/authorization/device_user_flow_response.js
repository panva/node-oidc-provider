const { get } = require('lodash');
const debug = require('debug')('oidc-provider:authentication:success');

const instance = require('../../helpers/weak_cache');

module.exports = provider => async function deviceVerificationResponse(ctx, next) {
  const { deviceCodeSuccess } = instance(provider).configuration();
  const code = ctx.oidc.deviceCode;

  Object.assign(code, {
    accountId: ctx.oidc.session.accountId(),
    acr: ctx.oidc.acr,
    amr: ctx.oidc.amr,
    authTime: ctx.oidc.session.authTime(),
    claims: ctx.oidc.claims,
    scope: ctx.oidc.params.scope,
  });

  if (ctx.oidc.client.includeSid() || get(ctx.oidc.claims, 'id_token.sid')) {
    code.sid = ctx.oidc.session.sidFor(ctx.oidc.client.clientId);
  }

  await code.save();

  await deviceCodeSuccess(ctx);

  provider.emit('authorization.success', ctx);
  debug('uuid=%s %o', ctx.oidc.uuid, {});

  await next();
};
