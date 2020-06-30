const instance = require('../../../weak_cache');
const Check = require('../../check');

module.exports = () => new Check('claims_id_token_sub_value', 'requested subject could not be obtained', async (ctx) => {
  const { oidc } = ctx;

  if (!oidc.claims.id_token || !oidc.claims.id_token.sub || !('value' in oidc.claims.id_token.sub)) {
    return false;
  }

  let sub = oidc.session.accountId();
  if (sub === undefined) {
    return true;
  }

  if (oidc.client.sectorIdentifier) {
    sub = await instance(oidc.provider).configuration('pairwiseIdentifier')(ctx, sub, oidc.client);
  }

  if (oidc.claims.id_token.sub.value !== sub) {
    return true;
  }

  return false;
}, ({ oidc }) => ({ sub: oidc.claims.id_token.sub }));
