const { InvalidRequest, UnsupportedResponseMode } = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');
const { isFrontChannel } = require('../../helpers/resolve_response_mode');

/*
 * Resolves and assigns params.response_mode if it was not explicitly requested. Validates id_token
 * and token containing responses do not use response_mode query.
 *
 * @throws: invalid_request
 */
module.exports = function checkResponseMode(ctx, next) {
  const { params, client } = ctx.oidc;

  const frontChannel = isFrontChannel(params.response_type);

  const mode = ctx.oidc.responseMode;

  if (
    mode !== undefined
    && !instance(ctx.oidc.provider).responseModes.has(mode)
  ) {
    params.response_mode = undefined;
    throw new UnsupportedResponseMode();
  }

  if (
    mode !== undefined && mode.includes('jwt')
    && (
      /^HS/.test(client.authorizationSignedResponseAlg)
      || /^(A|P|dir$)/.test(client.authorizationEncryptedResponseAlg)
    )
  ) {
    try {
      client.checkClientSecretExpiration('client secret is expired, cannot issue a JWT Authorization response');
    } catch (err) {
      const [explicit] = mode === 'jwt' ? [undefined] : mode.split('.');
      params.response_mode = explicit || undefined;
      throw err;
    }
  }

  if (mode === 'query' && frontChannel) {
    throw new InvalidRequest('response_mode not allowed for this response_type');
  } else if (mode === 'query.jwt' && frontChannel && !client.authorizationEncryptedResponseAlg) {
    throw new InvalidRequest('response_mode not allowed for this response_type unless encrypted');
  }

  return next();
};
