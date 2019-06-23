const Check = require('../../check');

module.exports = () => new Check('scopes_missing', 'requested scopes not granted by End-User', (ctx) => {
  const { oidc } = ctx;
  const promptedScopes = oidc.session.promptedScopesFor(oidc.client.clientId);

  for (const scope of oidc.requestParamScopes) { // eslint-disable-line no-restricted-syntax
    if (!promptedScopes.has(scope)) {
      return true;
    }
  }

  return false;
});
