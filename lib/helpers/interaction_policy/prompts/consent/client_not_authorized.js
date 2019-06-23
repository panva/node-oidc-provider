const Check = require('../../check');

module.exports = () => new Check('client_not_authorized', 'client not authorized for End-User session yet', 'interaction_required', (ctx) => {
  const { oidc } = ctx;
  if (oidc.session.sidFor(oidc.client.clientId)) {
    return false;
  }

  return true;
});
