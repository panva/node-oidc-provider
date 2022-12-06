import { InvalidScope } from '../../helpers/errors.js';
import instance from '../../helpers/weak_cache.js';

/*
 * Validates that all requested scopes are supported by the provider, and that offline_access prompt
 * is requested together with consent prompt
 *
 * @throws: invalid_request
 */
export default async function checkScope(PARAM_LIST, ctx, next) {
  const { scopes: statics } = instance(ctx.oidc.provider).configuration();
  const { prompts, client } = ctx.oidc;

  const scopes = ctx.oidc.params.scope ? [...new Set(ctx.oidc.params.scope.split(' '))] : [];

  const responseType = ctx.oidc.params.response_type;

  /*
   * Upon receipt of a scope parameter containing the offline_access value, the Authorization Server
   *
   * MUST ensure that the prompt parameter contains consent
   * MUST ignore the offline_access request unless the Client is using a response_type value that
   *  would result in an Authorization Code being returned,
   *
   * Furthermore no offline_access will be granted if the client doesn't have the grant allowed
   */

  if (scopes.includes('offline_access')) {
    if (
      (PARAM_LIST.has('response_type') && !responseType.includes('code'))
      || (PARAM_LIST.has('prompt') && !prompts.has('consent'))
      || !client.grantTypeAllowed('refresh_token')
    ) {
      scopes.splice(scopes.indexOf('offline_access'), 1);
    }
  }

  if (scopes.length) {
    ctx.oidc.params.scope = scopes.join(' ');
  } else {
    ctx.oidc.params.scope = undefined;
  }

  if (client.scope) {
    const allowList = new Set(client.scope.split(' '));

    for (const scope of scopes.filter(Set.prototype.has.bind(statics))) {
      if (!allowList.has(scope)) {
        throw new InvalidScope('requested scope is not allowed', scope);
      }
    }
  }

  return next();
}
