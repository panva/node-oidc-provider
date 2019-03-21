const instance = require('../../../weak_cache');
const errors = require('../../../errors');
const Check = require('../../check');

module.exports = new Check('id_token_hint', 'id_token_hint and authenticated subject do not match', async (ctx) => {
  const { oidc } = ctx;
  const hint = oidc.params.id_token_hint;
  if (hint === undefined) {
    return false;
  }

  let payload;
  try {
    ({ payload } = await oidc.provider.IdToken.validate(hint, oidc.client));
  } catch (err) {
    throw new errors.InvalidRequest(`could not validate id_token_hint (${err.message})`);
  }

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
