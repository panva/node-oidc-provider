const errors = require('../helpers/errors');
const instance = require('../helpers/weak_cache');
const JWT = require('../helpers/jwt');

module.exports = function getTokenJwtAuth(provider, endpoint) {
  return async function tokenJwtAuth(ctx, keystore, algorithms) {
    const uniqueCheck = instance(provider).configuration('uniqueness');
    const endpointUri = ctx.oidc.urlFor(endpoint);

    ctx.assert(ctx.oidc.params.client_assertion,
      new errors.InvalidRequestError('client_assertion must be provided'));

    ctx.assert(ctx.oidc.params.client_assertion_type ===
      'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', new errors.InvalidRequestError(
        'client_assertion_type must have value ' +
        'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'));

    const decoded = (() => {
      try {
        return JWT.decode(ctx.oidc.params.client_assertion);
      } catch (err) {
        return ctx.throw(new errors.InvalidRequestError('client_assertion could not be decoded'));
      }
    })();

    const header = decoded.header;
    const payload = decoded.payload;

    ctx.assert(payload && header, new errors.InvalidRequestError(
      'could not parse client_assertion as valid JWT'));

    ctx.assert(algorithms.indexOf(header.alg) !== -1,
      new errors.InvalidRequestError('alg mismatch'));

    ctx.assert(payload.exp, new errors.InvalidRequestError(
      'expiration must be specified in the client_assertion JWT'));

    ctx.assert(payload.jti, new errors.InvalidRequestError(
      'unique jti (JWT ID) must be provided in the client_assertion JWT'));

    ctx.assert(payload.iss, new errors.InvalidRequestError(
      'iss (JWT issuer) must be provided in the client_assertion JWT'));

    ctx.assert(payload.iss === ctx.oidc.client.clientId,
      new errors.InvalidRequestError('issuer (iss) must be the client id'));

    ctx.assert(payload.aud, new errors.InvalidRequestError(
      'aud (JWT audience) must be provided in the client_assertion JWT'));

    if (Array.isArray(payload.aud)) {
      ctx.assert(payload.aud.indexOf(endpointUri) !== -1, new errors.InvalidRequestError(
        'list of audience (aud) must include the endpoint url'));
    } else {
      ctx.assert(payload.aud === endpointUri, new errors.InvalidRequestError(
        'audience (aud) must equal the endpoint url'));
    }

    ctx.assert(payload.sub, new errors.InvalidRequestError(
      'sub (JWT subject) must be provided in the client_assertion JWT'));

    ctx.assert(payload.sub === ctx.oidc.client.clientId,
      new errors.InvalidRequestError('sub (JWT subject) must be the client id'));

    const unique = await uniqueCheck(ctx, payload.jti, payload.exp);
    ctx.assert(unique, new errors.InvalidRequestError('jwt-bearer tokens must only be used once'));

    try {
      await JWT.verify(ctx.oidc.params.client_assertion, keystore, {
        audience: endpointUri,
        issuer: ctx.oidc.client.clientId,
      });
    } catch (err) {
      ctx.throw(new errors.InvalidClientError(err.message));
    }
  };
};
