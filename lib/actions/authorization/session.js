import { account as validateAccount } from '../../helpers/configuration_result.js';
import instance from '../../helpers/weak_cache.js';

/*
 * Loads the End-User's account referenced by the session.
 */
export async function loadAccount(ctx, next) {
  const { accountId } = ctx.oidc.session;

  if (accountId) {
    const account = validateAccount(
      await instance(ctx.oidc.provider).configuration.findAccount(ctx, accountId),
    );
    ctx.oidc.entity('Account', account);
  }

  return next();
}

/*
 * Load or establish a new Grant object when the user is known.
 */
export async function loadGrant(ctx, next) {
  const { loadExistingGrant } = instance(ctx.oidc.provider).configuration;
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
