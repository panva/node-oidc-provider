import { account as validateAccount } from '../../helpers/configuration_result.js';
import instance from '../../helpers/weak_cache.js';

/*
 * Loads the End-User's account referenced by the session.
 */
export default async function loadAccount(ctx, next) {
  const { accountId } = ctx.oidc.session;

  if (accountId) {
    const account = validateAccount(
      await instance(ctx.oidc.provider).configuration.findAccount(ctx, accountId),
    );
    ctx.oidc.entity('Account', account);
  }

  return next();
}
