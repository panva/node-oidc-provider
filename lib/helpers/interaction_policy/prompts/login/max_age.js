const Check = require('../../check');

module.exports = () => new Check('max_age', 'End-User authentication could not be obtained', (ctx) => {
  const { oidc } = ctx;
  if (oidc.params.max_age === undefined) {
    return false;
  }

  if (!oidc.session.accountId()) {
    return true;
  }

  if (oidc.session.past(oidc.params.max_age) && (!ctx.oidc.result || !ctx.oidc.result.login)) {
    return true;
  }

  return false;
});
