const { InvalidRequestError } = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');

const ALLOWED = ['plain', 'S256'];

/*
 * (optional[true]) assign default code_challenge_method if a code_challenge is provided
 * (optional[true]) check presence of code code_challenge if code_challenge_method is provided
 * (feature|optional[false]) enforce PKCE use for native clients using hybrid or code flow
 */
module.exports = (provider) => {
  const pkce = instance(provider).configuration('features.pkce');
  return async function checkPixy(ctx, next) {
    const params = ctx.oidc.params;

    if (pkce && params.code_challenge_method) {
      ctx.assert(ALLOWED.indexOf(params.code_challenge_method) !== -1,
        new InvalidRequestError('not supported value of code_challenge_method'));

      ctx.assert(params.code_challenge,
        new InvalidRequestError('code_challenge must be provided with code_challenge_method'));
    }

    if (pkce && !params.code_challenge_method && params.code_challenge) {
      params.code_challenge_method = 'plain';
    }

    const forced = pkce &&
      pkce.forcedForNative &&
      params.response_type.includes('code') &&
      ctx.oidc.client.applicationType === 'native';

    if (forced) {
      ctx.assert(params.code_challenge,
        new InvalidRequestError('PKCE must be provided for native clients'));
    }

    await next();
  };
};
