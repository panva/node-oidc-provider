const instance = require('../../../weak_cache');
const Check = require('../../check');

module.exports = () => new Check('id_token_hint', 'id_token_hint and authenticated subject do not match', async (ctx) => {
  const { oidc } = ctx;
  if (oidc.entities.IdTokenHint === undefined) {
    return false;
  }

  const { payload } = oidc.entities.IdTokenHint;

  let sub = oidc.session.accountId();
  if (sub === undefined) {
    return true;
  }

  if (oidc.client.sectorIdentifier) {
    sub = await instance(oidc.provider).configuration('pairwiseIdentifier')(ctx, sub, oidc.client);
  }

  if (payload.sub !== sub) {
    return true;
  }

  return false;
});
