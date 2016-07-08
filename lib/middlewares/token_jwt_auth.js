'use strict';

const errors = require('../helpers/errors');
const JWT = require('../helpers/jwt');

module.exports = function getTokenJwtAuth(provider) {
  return function * tokenJwtAuth(keystore, algorithms) {
    const tokenUri = this.oidc.urlFor('token');

    this.assert(this.oidc.params.client_assertion,
      new errors.InvalidRequestError('client_assertion must be provided'));

    this.assert(this.oidc.params.client_assertion_type ===
      'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        new errors.InvalidRequestError(
          'client_assertion_type must have value ' +
          'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'));

    let decoded;
    try {
      decoded = JWT.decode(this.oidc.params.client_assertion);
    } catch (err) {
      this.throw(new errors.InvalidRequestError('client_assertion could not be decoded'));
    }

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
      this.assert(payload.aud.indexOf(tokenUri) !== -1,
        new errors.InvalidRequestError(
          'list of audience (aud) must include the token endpoint url'));
    } else {
      this.assert(payload.aud === tokenUri, new errors.InvalidRequestError(
        'audience (aud) must equal the token endpoint url'));
    }

    this.assert(payload.sub, new errors.InvalidRequestError(
      'sub (JWT subject) must be provided in the client_assertion JWT'));

    this.assert(payload.sub === this.oidc.client.clientId,
      new errors.InvalidRequestError(
        'sub (JWT subject) must be the client id'));
    const uniqueCheck = provider.configuration('uniqueness');
    const unique = yield uniqueCheck(this, payload.jti, payload.exp);
    this.assert(unique, new errors.InvalidRequestError(
      'jwt-bearer tokens must only be used once'));

    try {
      yield keystore.refresh();
      yield JWT.verify(this.oidc.params.client_assertion, keystore, {
        audience: tokenUri,
        issuer: this.oidc.client.clientId,
      });
    } catch (err) {
      this.throw(new errors.InvalidClientError(err.message));
    }
  };
};
