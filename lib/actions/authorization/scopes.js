import { InvalidScope, InvalidRequest } from '../../helpers/errors.js';
import isValidScope from '../../helpers/is_valid_scope.js';
import instance from '../../helpers/weak_cache.js';

/*
 * Validates that all requested scopes are supported by the provider, and that offline_access prompt
 * is requested together with consent prompt
 */
export async function checkScope(PARAM_LIST, ctx, next) {
  const { scopes: statics } = instance(ctx.oidc.provider).configuration;
  const { prompts, client } = ctx.oidc;

  if (!isValidScope(ctx.oidc.params.scope)) {
    throw new InvalidScope('scope contains invalid characters');
  }

  const scopes = [...new Set(ctx.oidc.params.scope?.split(' '))];

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

const GATED_CLIENT = Object.entries({
  defaultAcrValues: 'default_acr_values',
  defaultMaxAge: 'default_max_age',
  requireAuthTime: 'require_auth_time',
});

const GATED = [
  'acr_values',
  'claims',
  'claims_locales',
  'id_token_hint',
  'max_age',
  'nonce',
];

/*
 * Validates that openid scope is requested when openid specific parameters are provided
 */
function checkOpenIdScope(PARAM_LIST, ctx, next) {
  if (ctx.oidc.params.scope?.split(' ').includes('openid')) {
    return next();
  }

  if (PARAM_LIST.has('response_type') && ctx.oidc.params.response_type.includes('id_token')) {
    throw new InvalidRequest('openid scope must be requested for this response_type');
  }

  GATED_CLIENT.forEach(([prop, msg]) => {
    if (ctx.oidc.client[prop]) {
      throw new InvalidRequest(`openid scope must be requested for clients with ${msg}`);
    }
  });

  GATED.forEach((param) => {
    if (ctx.oidc.params[param] !== undefined) {
      throw new InvalidRequest(`openid scope must be requested when using the ${param} parameter`);
    }
  });

  if (ctx.oidc.route === 'backchannel_authentication') {
    throw new InvalidRequest('openid scope must be requested for this request');
  }

  return next();
}

export { checkOpenIdScope as checkOpenidScope };
