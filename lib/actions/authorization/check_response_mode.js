const { InvalidRequest, UnsupportedResponseMode } = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');
const { isImplicit } = require('../../helpers/resolve_response_mode');

/*
 * Resolves and assigns params.response_mode if it was not explicitly requested. Validates id_token
 * and token containing responses do not use response_mode query.
 *
 * @throws: invalid_request
 */
module.exports = provider => async function checkResponseMode(ctx, next) {
  const { params, client } = ctx.oidc;

  const implicitOrHybrid = isImplicit(params.response_type);

  if (params.response_mode === undefined) {
    params.response_mode = implicitOrHybrid ? 'fragment' : 'query';
  } else if (params.response_mode === 'query' && implicitOrHybrid) {
    throw new InvalidRequest('response_mode not allowed for this response_type');
  } else if (params.response_mode === 'query.jwt' && implicitOrHybrid && !client.authorizationEncryptedResponseAlg) {
    throw new InvalidRequest('response_mode not allowed for this response_type unless encrypted');
  }

  if (!instance(provider).responseModes.has(params.response_mode)) {
    params.response_mode = undefined;
    throw new UnsupportedResponseMode();
  }

  await next();
};
