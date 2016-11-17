'use strict';

/*
 * Loads the End-User's account referenced by the session.
 */
module.exports = provider => async function loadAccount(ctx, next) {
  const accountId = ctx.oidc.session.accountId();

  if (accountId) {
    const Account = provider.Account;
    ctx.oidc.account = await Account.findById(accountId);
  }

  await next();
};
