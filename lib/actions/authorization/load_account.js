/*
 * Loads the End-User's account referenced by the session.
 */
module.exports = ({ Account }) => async function loadAccount(ctx, next) {
  const accountId = ctx.oidc.session.accountId();

  if (accountId) {
    const account = await Account.findById(ctx, accountId);
    ctx.oidc.entity('Account', account);
  }

  await next();
};
