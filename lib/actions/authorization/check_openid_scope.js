const { InvalidRequest } = require('../../helpers/errors');

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
 *
 * @throws: invalid_request
 */
module.exports = function checkScope(PARAM_LIST, ctx, next) {
  const present = !!ctx.oidc.params.scope;
  const openid = present && ctx.oidc.params.scope.split(' ').includes('openid');

  if (openid) {
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

  return next();
};
