const { InvalidRequest, UnsupportedResponseMode } = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');

/*
 * Resolves and assigns params.response_mode if it was not explicitly requested. Validates id_token
 * and token containing responses do not use response_mode query.
 *
 * @throws: invalid_request
 */
module.exports = provider => async function checkResponseMode(ctx, next) {
  const { params } = ctx.oidc;

  if (params.response_mode === undefined) {
    params.response_mode = String(params.response_type).includes('token') ? 'fragment' : 'query';
  } else {
    const invalid = params.response_mode === 'query' && params.response_type.includes('token');

    if (invalid) {
      ctx.throw(new InvalidRequest('response_mode not allowed for this response_type'));
    }
  }

  if (!instance(provider).responseModes.has(params.response_mode)) {
    params.response_mode = undefined;
    ctx.throw(new UnsupportedResponseMode());
  }

  await next();
};
