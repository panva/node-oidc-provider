const instance = require('../../helpers/weak_cache');

module.exports = async function backchannelRequestResponse(ctx, next) {
  const { BackchannelAuthenticationRequest } = ctx.oidc.provider;
  const { features: { ciba } } = instance(ctx.oidc.provider).configuration();

  const request = new BackchannelAuthenticationRequest({
    accountId: ctx.oidc.account.accountId,
    claims: ctx.oidc.claims,
    client: ctx.oidc.client,
    nonce: ctx.oidc.params.nonce,
    params: ctx.oidc.params.toPlainObject(),
    resource: Object.keys(ctx.oidc.resourceServers),
    scope: [...ctx.oidc.requestParamScopes].join(' '),
  });

  ctx.oidc.entity('BackchannelAuthenticationRequest', request);

  const id = await request.save();

  ctx.body = {
    expires_in: request.expiration,
    auth_req_id: id,
  };

  await ciba.triggerAuthenticationDevice(ctx, request, ctx.oidc.account, ctx.oidc.client);

  return next();
};
