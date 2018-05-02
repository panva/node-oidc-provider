const { isEmpty } = require('lodash');
const { InvalidRequest } = require('../../helpers/errors');

/*
 * Validates presence of mandatory OpenID Connect parameters redirect_uri and conditionally nonce if
 * id_token issued directly by the authorization response.
 *
 * @throws: invalid_request
 */
module.exports = async function oidcRequired(ctx, next) {
  // Validate: required params
  const { params } = ctx.oidc;
  const missing = [];

  if (params.redirect_uri === undefined) missing.push('redirect_uri');

  // Second check for nonce if id_token is involved
  if (params.response_type && !params.nonce && params.response_type.includes('token')) {
    missing.push('nonce');
  }

  if (!isEmpty(missing)) {
    ctx.throw(new InvalidRequest(`missing required parameter(s) ${missing.join(',')}`));
  }

  await next();
};
