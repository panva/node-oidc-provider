const Check = require('../../check');

module.exports = () => new Check('no_session', 'End-User authentication is required', (ctx) => {
  const { oidc } = ctx;
  if (oidc.session.accountId()) {
    return false;
  }

  return true;
});
