const Check = require('../../check');

module.exports = () => new Check('claims_missing', 'requested claims not granted by End-User', (ctx) => {
  const { oidc } = ctx;
  const promptedClaims = oidc.session.promptedClaimsFor(oidc.client.clientId);

  for (const claim of oidc.requestParamClaims) { // eslint-disable-line no-restricted-syntax
    if (!promptedClaims.has(claim) && !['sub', 'sid', 'auth_time', 'acr', 'amr', 'iss'].includes(claim)) {
      return true;
    }
  }

  return false;
});
