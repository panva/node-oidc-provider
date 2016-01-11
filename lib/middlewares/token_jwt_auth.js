'use strict';

let _ = require('lodash');

let errors = require('../helpers/errors');
let JWT = require('../helpers/jwt');

module.exports = function(provider) {
  let uniqueness = provider.configuration.uniqueness;

  return function * tokenJwtAuth(keystore, algorithms) {
    let tokenUri = this.oidc.urlFor('token');

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
      this.throw(new errors.InvalidClientError());
    }

    let header = decoded.header;
    let payload = decoded.payload;

    this.assert(payload && header, new errors.InvalidRequestError(
      'could not parse client_assertion as valid JWT'));

    this.assert(algorithms.indexOf(header.alg) !== -1,
      new errors.InvalidRequestError('alg mismatch'));

    this.assert(payload.exp, new errors.InvalidRequestError(
      'expiration must be specified in the client_assertion JWT'));

    this.assert(payload.jti, new errors.InvalidRequestError(
      'unique jti (JWT ID) must be provided in the client_assertion JWT'));

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

    this.assert(payload.sub === this.oidc.client.clientId,
      new errors.InvalidRequestError(
        'subject (sub) must equal your client id'));

    let unique = yield uniqueness(payload.jti, payload.exp);
    this.assert(unique, new errors.InvalidRequestError(
      'jwt-bearer tokens must only be used once'));

    try {
      // TODO: only refresh when needed
      yield keystore.refresh();
      yield JWT.verify(this.oidc.params.client_assertion, keystore, {
        issuer: this.oidc.client.clientId,
      });
    } catch (err) {
      this.throw(new errors.InvalidClientError());
    }
  };
};
