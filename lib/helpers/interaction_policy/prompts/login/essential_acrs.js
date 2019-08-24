const get = require('lodash/get');

const errors = require('../../../errors');
const Check = require('../../check');

module.exports = () => new Check('essential_acrs', 'none of the requested ACRs could not be obtained', (ctx) => {
  const { oidc } = ctx;
  const request = get(oidc.claims, 'id_token.acr', {});

  if (!request || !request.essential || !request.values) {
    return false;
  }

  if (!Array.isArray(oidc.claims.id_token.acr.values)) {
    throw new errors.InvalidRequest('invalid claims.id_token.acr.values type');
  }

  if (request.values.includes(oidc.acr)) {
    return false;
  }

  return true;
}, ({ oidc }) => ({ acr: oidc.claims.id_token.acr }));
