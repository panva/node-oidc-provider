const pull = require('lodash/pull');

const instance = require('../../helpers/weak_cache');
const { InvalidScope } = require('../../helpers/errors');
const { DYNAMIC_SCOPE_LABEL } = require('../../consts');

/*
 * Validates that all requested scopes are supported by the provider, and that offline_access prompt
 * is requested together with consent prompt
 *
 * @throws: invalid_request
 */
module.exports = function checkScope(PARAM_LIST, ctx, next) {
  const { scopes: statics, dynamicScopes: dynamics } = instance(ctx.oidc.provider).configuration();
  const { prompts, client } = ctx.oidc;

  let whitelist;
  if (client.scope) {
    whitelist = new Set(client.scope.split(' '));
  }

  const scopes = (ctx.oidc.params.scope || '').split(' ').filter((scope) => {
    if (statics.has(scope)) {
      if (whitelist && !whitelist.has(scope)) {
        throw new InvalidScope('requested scope is not whitelisted', scope);
      }
      return true;
    }

    for (const dynamic of dynamics) { // eslint-disable-line no-restricted-syntax
      if (dynamic.test(scope)) {
        if (whitelist && !whitelist.has(dynamic[DYNAMIC_SCOPE_LABEL])) {
          throw new InvalidScope('requested scope is not whitelisted', scope);
        }
        return true;
      }
    }

    return false;
  });

  const responseType = ctx.oidc.params.response_type;

  /*
   * Upon receipt of a scope parameter containing the offline_access value, the Authorization Server
   *
   * MUST ensure that the prompt parameter contains consent
   * MUST ignore the offline_access request unless the Client is using a response_type value that
   *  would result in an Authorization Code being returned,
   *
   * Furthermore no offline_access will be granted if the client doesn't have the grant whitelisted
   */

  if (scopes.includes('offline_access')) {
    if (
      (PARAM_LIST.has('response_type') && !responseType.includes('code'))
      || !prompts.has('consent')
      || !client.grantTypes.includes('refresh_token')
    ) {
      pull(scopes, 'offline_access');
    }
  }

  if (scopes.length) {
    ctx.oidc.params.scope = scopes.join(' ');
  } else {
    ctx.oidc.params.scope = undefined;
  }

  return next();
};
