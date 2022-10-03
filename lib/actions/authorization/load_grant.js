const instance = require('../../helpers/weak_cache');

/*
 * Load or establish a new Grant object when the user is known.
 */
module.exports = async function loadGrant(ctx, next) {
  const loadExistingGrant = instance(ctx.oidc.provider).configuration('loadExistingGrant');
  if (ctx.oidc.account) {
    let grant = await loadExistingGrant(ctx);
    if (grant) {
      if (grant.accountId !== ctx.oidc.account.accountId) {
        throw new Error('accountId mismatch');
      }
      if (grant.clientId !== ctx.oidc.client.clientId) {
        throw new Error('clientId mismatch');
      }
      ctx.oidc.session.ensureClientContainer(ctx.oidc.params.client_id);
      // TODO: what if the returned Grant is a new instance and not saved yet?
      ctx.oidc.session.grantIdFor(ctx.oidc.params.client_id, grant.jti);
    } else {
      grant = new ctx.oidc.provider.Grant({
        accountId: ctx.oidc.account.accountId,
        clientId: ctx.oidc.client.clientId,
      });
    }
    ctx.oidc.entity('Grant', grant);
  }

  return next();
};
