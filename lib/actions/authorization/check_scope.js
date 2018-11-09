const { pull } = require('lodash');

const instance = require('../../helpers/weak_cache');
/*
 * Validates that all requested scopes are supported by the provider, that openid is amongst them
 * and that offline_access prompt is requested together with consent scope
 *
 * @throws: invalid_request
 */
module.exports = (provider, PARAM_LIST) => async function checkScope(ctx, next) {
  const { scopes: statics, dynamicScopes: dynamics } = instance(provider).configuration();

  const scopes = ctx.oidc.params.scope.split(' ').filter((scope) => {
    if (statics.includes(scope)) {
      return true;
    }

    for (const dynamic of dynamics) { // eslint-disable-line no-restricted-syntax
      if (dynamic.test(scope)) {
        return true;
      }
    }

    return false;
  });

  const responseType = ctx.oidc.params.response_type;
  const { prompts } = ctx.oidc;

  /*
   * Upon receipt of a scope parameter containing the offline_access value, the Authorization Server
   *
   * MUST ensure that the prompt parameter contains consent
   * MUST ignore the offline_access request unless the Client is using a response_type value that
   *  would result in an Authorization Code being returned,
   */

  if (scopes.includes('offline_access')) {
    if ((PARAM_LIST.has('response_type') && !responseType.includes('code')) || !prompts.includes('consent')) {
      pull(scopes, 'offline_access').join(' ');
    }
  }

  ctx.oidc.params.scope = scopes.join(' ');

  await next();
};
