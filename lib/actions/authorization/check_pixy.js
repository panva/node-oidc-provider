const { InvalidRequest } = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');

/*
 * (optional[true]) assign default code_challenge_method if a code_challenge is provided
 * (optional[true]) check presence of code code_challenge if code_challenge_method is provided
 * (feature|optional[false]) enforce PKCE use for native clients using hybrid or code flow
 */
module.exports = (provider) => {
  const pkce = instance(provider).configuration('features.pkce');
  return async function checkPixy(ctx, next) {
    const { params } = ctx.oidc;

    if (pkce && !params.code_challenge_method && params.code_challenge) {
      params.code_challenge_method = 'plain';
    }

    if (pkce && params.code_challenge_method) {
      if (!pkce.supportedMethods.includes(params.code_challenge_method)) {
        ctx.throw(new InvalidRequest('not supported value of code_challenge_method'));
      }

      if (!params.code_challenge) {
        ctx.throw(new InvalidRequest('code_challenge must be provided with code_challenge_method'));
      }
    }

    const forced = pkce &&
      pkce.forcedForNative &&
      params.response_type.includes('code') &&
      ctx.oidc.client.applicationType === 'native';

    if (forced && !params.code_challenge) {
      ctx.throw(new InvalidRequest('PKCE must be provided for native clients'));
    }

    await next();
  };
};
