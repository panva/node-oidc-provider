import { InvalidRequest, OIDCProviderError } from '../../helpers/errors.js';

/*
 * Validates the incoming id_token_hint
 */
export default async function checkIdTokenHint(ctx, next) {
  const { oidc } = ctx;
  if (oidc.params.id_token_hint !== undefined) {
    let idTokenHint;
    try {
      idTokenHint = await oidc.provider.IdToken.validate(oidc.params.id_token_hint, oidc.client);
    } catch (cause) {
      if (cause instanceof OIDCProviderError) {
        throw cause;
      }

      throw new InvalidRequest('could not validate id_token_hint', undefined, { cause });
    }
    ctx.oidc.entity('IdTokenHint', idTokenHint);
  }

  return next();
}
