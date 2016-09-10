'use strict';

/*
 * Loads the End-User's account referenced by the session.
 */
module.exports = provider => function* loadAccount(next) {
  const accountId = this.oidc.session.accountId();

  if (accountId) {
    const Account = provider.Account;
    this.oidc.account = yield Account.findById(accountId);
  }

  yield next;
};
