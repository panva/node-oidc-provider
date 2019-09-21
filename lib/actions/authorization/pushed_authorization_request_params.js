const { InvalidRequest } = require('../../helpers/errors');

/*
 * Makes sure that
 * - unauthenticated clients send the JAR Request Object
 * - either JAR or plain request is provided
 * - request_uri is not used
 *
 * @throws: invalid_request
 */
module.exports = function pushedAuthorizationRequestParams(ctx, next) {
  const JAR = !!ctx.oidc.params.request;

  if (
    ctx.oidc.client.requestObjectSigningAlg
    && ctx.oidc.client.tokenEndpointAuthMethod === 'none'
    && !JAR
  ) {
    throw new InvalidRequest('Request Object must be used by this client');
  }

  for (const [param, value] of Object.entries(ctx.oidc.params)) { // eslint-disable-line no-restricted-syntax, max-len
    if (value !== undefined) {
      if (JAR && (param !== 'client_id' && param !== 'request')) {
        throw new InvalidRequest('`request` parameter must not be combined with other parameters at the pushed_authorization_request_endpoint');
      }
      if (param === 'request_uri') {
        throw new InvalidRequest('`request_uri` parameter must not be used at the pushed_authorization_request_endpoint');
      }
    }
  }

  return next();
};
