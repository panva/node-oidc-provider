const { InvalidRequestError, InvalidClientError } = require('../helpers/errors');
const instance = require('../helpers/weak_cache');
const JWT = require('../helpers/jwt');

const TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

module.exports = function getTokenJwtAuth(provider, endpoint) {
  return async function tokenJwtAuth(ctx, keystore, algorithms) {
    const uniqueCheck = instance(provider).configuration('uniqueness');
    const endpointUri = ctx.oidc.urlFor(endpoint);

    if (!ctx.oidc.params.client_assertion) {
      ctx.throw(new InvalidRequestError('client_assertion must be provided'));
    }

    if (ctx.oidc.params.client_assertion_type !== TYPE) {
      ctx.throw(new InvalidRequestError(`client_assertion_type must have value ${TYPE}`));
    }

    const decoded = (() => {
      try {
        return JWT.decode(ctx.oidc.params.client_assertion);
      } catch (err) {
        return ctx.throw(new InvalidRequestError('client_assertion could not be decoded'));
      }
    })();

    const { header, payload } = decoded;

    ctx.assert(
      payload && header,
      new InvalidRequestError('could not parse client_assertion as valid JWT'),
    );

    if (!algorithms.includes(header.alg)) {
      ctx.throw(new InvalidRequestError('alg mismatch'));
    }

    if (!payload.exp) {
      ctx.throw(new InvalidRequestError('expiration must be specified in the client_assertion JWT'));
    }

    if (!payload.jti) {
      ctx.throw(new InvalidRequestError('unique jti (JWT ID) must be provided in the client_assertion JWT'));
    }

    if (!payload.iss) {
      ctx.throw(new InvalidRequestError('iss (JWT issuer) must be provided in the client_assertion JWT'));
    }

    if (payload.iss !== ctx.oidc.client.clientId) {
      ctx.throw(new InvalidRequestError('issuer (iss) must be the client id'));
    }

    if (!payload.aud) {
      ctx.throw(new InvalidRequestError('aud (JWT audience) must be provided in the client_assertion JWT'));
    }

    if (Array.isArray(payload.aud)) {
      if (!payload.aud.includes(endpointUri)) {
        ctx.throw(new InvalidRequestError('list of audience (aud) must include the endpoint url'));
      }
    } else if (payload.aud !== endpointUri) {
      ctx.throw(new InvalidRequestError('audience (aud) must equal the endpoint url'));
    }

    // the following is already covered by find_client_id middleware
    // if (!payload.sub) {
    //   ctx.throw(new InvalidRequestError(
    //     'sub (JWT subject) must be provided in the client_assertion JWT'));
    // }
    //
    // if (payload.sub !== ctx.oidc.client.clientId) {
    //   ctx.throw(new InvalidRequestError('sub (JWT subject) must be the client id'));
    // }

    const unique = await uniqueCheck(ctx, payload.jti, payload.exp);

    if (!unique) {
      ctx.throw(new InvalidRequestError('jwt-bearer tokens must only be used once'));
    }

    try {
      await JWT.verify(ctx.oidc.params.client_assertion, keystore, {
        audience: endpointUri,
        issuer: ctx.oidc.client.clientId,
        clockTolerance: instance(provider).configuration('clockTolerance'),
      });
    } catch (err) {
      ctx.throw(new InvalidClientError(err.message));
    }
  };
};
