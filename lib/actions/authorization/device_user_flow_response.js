const has = require('lodash/has');
const debug = require('debug')('oidc-provider:authentication:success');

const instance = require('../../helpers/weak_cache');

module.exports = async function deviceVerificationResponse(ctx, next) {
  const {
    expiresWithSession,
    features: { deviceFlow: { successSource }, resourceIndicators },
  } = instance(ctx.oidc.provider).configuration();
  const code = ctx.oidc.deviceCode;

  const scope = ctx.oidc.acceptedScope();

  Object.assign(code, {
    accountId: ctx.oidc.session.accountId(),
    acr: ctx.oidc.acr,
    amr: ctx.oidc.amr,
    authTime: ctx.oidc.session.authTime(),
    claims: ctx.oidc.resolvedClaims(),
    grantId: ctx.oidc.session.grantIdFor(ctx.oidc.client.clientId),
    scope,
    sessionUid: ctx.oidc.session.uid,
  });

  if (await expiresWithSession(ctx, code)) {
    code.expiresWithSession = true;
  } else {
    ctx.oidc.session.authorizationFor(ctx.oidc.client.clientId).persistsLogout = true;
  }

  if (ctx.oidc.client.includeSid() || has(ctx.oidc.claims, 'id_token.sid')) {
    code.sid = ctx.oidc.session.sidFor(ctx.oidc.client.clientId);
  }

  if (resourceIndicators.enabled) {
    code.resource = ctx.oidc.params.resource;
  }

  await code.save();

  await successSource(ctx);

  ctx.oidc.provider.emit('authorization.success', ctx);
  debug('uid=%s %o', ctx.oidc.uid, {});

  return next();
};
