const { InvalidRequest } = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');
const checkFormat = require('../../helpers/pkce_format');

/*
 * - assign default code_challenge_method if a code_challenge is provided
 * - check presence of code code_challenge if code_challenge_method is provided
 * - enforce PKCE use for native clients using hybrid or code flow
 */
module.exports = function checkPKCE(ctx, next) {
  const { params, route } = ctx.oidc;
  const { pkce } = instance(ctx.oidc.provider).configuration();

  if (!params.code_challenge_method && params.code_challenge) {
    if (pkce.methods.includes('plain')) {
      params.code_challenge_method = 'plain';
    } else {
      throw new InvalidRequest('plain code_challenge_method fallback disabled, code_challenge_method must be provided');
    }
  }

  if (params.code_challenge_method) {
    if (!pkce.methods.includes(params.code_challenge_method)) {
      throw new InvalidRequest('not supported value of code_challenge_method');
    }

    if (!params.code_challenge) {
      throw new InvalidRequest('code_challenge must be provided with code_challenge_method');
    }
  }

  // checking for response_type presence disables the need for PKCE for device_code grant
  if (typeof params.response_type === 'string' && params.response_type.includes('code')) {
    if (
      !params.code_challenge
      && (
        pkce.required(ctx, ctx.oidc.client)
        || (ctx.oidc.fapiProfile === '1.0 Final' && route === 'pushed_authorization_request')
      )) {
      throw new InvalidRequest('Authorization Server policy requires PKCE to be used for this request');
    }
  }

  if (params.code_challenge !== undefined) {
    checkFormat(params.code_challenge, 'code_challenge');
  }

  return next();
};
