'use strict';

const errors = require('../helpers/errors');
const instance = require('../helpers/weak_cache');
const JWT = require('../helpers/jwt');

module.exports = function getTokenJwtAuth(provider, endpoint) {
  const uniqueCheck = instance(provider).configuration('uniqueness');

  return async function tokenJwtAuth(keystore, algorithms) {
    const endpointUri = this.oidc.urlFor(endpoint);

    this.assert(this.oidc.params.client_assertion,
      new errors.InvalidRequestError('client_assertion must be provided'));

    this.assert(this.oidc.params.client_assertion_type ===
      'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', new errors.InvalidRequestError(
        'client_assertion_type must have value ' +
        'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'));

    const decoded = (() => {
      try {
        return JWT.decode(this.oidc.params.client_assertion);
      } catch (err) {
        return this.throw(new errors.InvalidRequestError('client_assertion could not be decoded'));
      }
    })();

    const header = decoded.header;
    const payload = decoded.payload;

    this.assert(payload && header, new errors.InvalidRequestError(
      'could not parse client_assertion as valid JWT'));

    this.assert(algorithms.indexOf(header.alg) !== -1,
      new errors.InvalidRequestError('alg mismatch'));

    this.assert(payload.exp, new errors.InvalidRequestError(
      'expiration must be specified in the client_assertion JWT'));

    this.assert(payload.jti, new errors.InvalidRequestError(
      'unique jti (JWT ID) must be provided in the client_assertion JWT'));

    this.assert(payload.iss, new errors.InvalidRequestError(
      'iss (JWT issuer) must be provided in the client_assertion JWT'));

    this.assert(payload.iss === this.oidc.client.clientId,
      new errors.InvalidRequestError('issuer (iss) must be the client id'));

    this.assert(payload.aud, new errors.InvalidRequestError(
      'aud (JWT audience) must be provided in the client_assertion JWT'));

    if (Array.isArray(payload.aud)) {
      this.assert(payload.aud.indexOf(endpointUri) !== -1, new errors.InvalidRequestError(
        'list of audience (aud) must include the endpoint url'));
    } else {
      this.assert(payload.aud === endpointUri, new errors.InvalidRequestError(
        'audience (aud) must equal the endpoint url'));
    }

    this.assert(payload.sub, new errors.InvalidRequestError(
      'sub (JWT subject) must be provided in the client_assertion JWT'));

    this.assert(payload.sub === this.oidc.client.clientId,
      new errors.InvalidRequestError('sub (JWT subject) must be the client id'));

    const unique = await uniqueCheck.call(this, payload.jti, payload.exp);
    this.assert(unique, new errors.InvalidRequestError('jwt-bearer tokens must only be used once'));

    try {
      await JWT.verify(this.oidc.params.client_assertion, keystore, {
        audience: endpointUri,
        issuer: this.oidc.client.clientId,
      });
    } catch (err) {
      this.throw(new errors.InvalidClientError(err.message));
    }
  };
};
