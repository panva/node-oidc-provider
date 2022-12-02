import instance from '../../helpers/weak_cache.js';

/*
 * Load or establish a new Grant object when the user is known.
 */
export default async function loadGrant(ctx, next) {
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
}
