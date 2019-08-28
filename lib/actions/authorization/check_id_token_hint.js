const { InvalidRequest, OIDCProviderError } = require('../../helpers/errors');

/*
 * Validates the incoming id_token_hint
 *
 * @throws: invalid_request
 */
module.exports = async function checkIdTokenHint(ctx, next) {
  const { oidc } = ctx;
  if (oidc.params.id_token_hint !== undefined) {
    let idTokenHint;
    try {
      idTokenHint = await oidc.provider.IdToken.validate(oidc.params.id_token_hint, oidc.client);
    } catch (err) {
      if (err instanceof OIDCProviderError) {
        throw err;
      }

      throw new InvalidRequest(`could not validate id_token_hint (${err.message})`);
    }
    ctx.oidc.entity('IdTokenHint', idTokenHint);
  }

  return next();
};
