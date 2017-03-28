const { InvalidRequestError } = require('../../helpers/errors');

/*
 * Resolves and assigns params.response_mode if it was not explicitly requested. Validates id_token
 * and token containing responses do not use response_mode query.
 *
 * @throws: invalid_request
 */
module.exports = async function checkResponseMode(ctx, next) {
  const { params } = ctx.oidc;

  if (params.response_mode === undefined) {
    params.response_mode = String(params.response_type).includes('token') ? 'fragment' : 'query';
  } else {
    const invalid = params.response_mode === 'query' && params.response_type.includes('token');

    ctx.assert(!invalid, new InvalidRequestError(
      'response_mode not allowed for this response_type'));
  }


  await next();
};
