const get = require('lodash/get');

const Check = require('../../check');

module.exports = () => new Check('essential_acr', 'requested ACR could not be obtained', (ctx) => {
  const { oidc } = ctx;
  const request = get(oidc.claims, 'id_token.acr', {});

  if (!request || !request.essential || !request.value) {
    return false;
  }

  if (request.value === oidc.acr) {
    return false;
  }

  return true;
}, ({ oidc }) => ({ acr: oidc.claims.id_token.acr }));
