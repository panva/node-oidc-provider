'use strict';

const assert = require('assert');
const _ = require('lodash');
const JWT = require('../../helpers/jwt');
const PARAM_LIST = require('../../consts').PARAM_LIST;
const instance = require('../../helpers/weak_cache');

/*
 * Decrypts and validates the content of provided request parameter and replaces the parameters
 * provided via OAuth2.0 authorization request with these
 *
 * @throws: invalid_request_object
 */
module.exports = (provider) => {
  const map = instance(provider);
  const conf = map.configuration;

  return function* decodeRequest(next) {
    const params = this.oidc.params;

    if (params.request === undefined) {
      yield next;
      return;
    }

    if (conf('features.encryption') && params.request.split('.').length === 5) {
      try {
        const header = JWT.header(params.request);

        assert(conf('requestObjectEncryptionAlgValues').indexOf(header.alg) !== -1,
          'unsupported encrypted request alg');
        assert(conf('requestObjectEncryptionEncValues').indexOf(header.enc) !== -1,
          'unsupported encrypted request enc');

        const decrypted = yield JWT.decrypt(params.request, map.keystore);
        params.request = decrypted.payload.toString('utf8');
      } catch (err) {
        this.throw(400, 'invalid_request_object', {
          error_description: `could not decrypt request object (${err.message})`,
        });
      }
    }

    let decoded;

    try {
      decoded = JWT.decode(params.request);
    } catch (err) {
      this.throw(400, 'invalid_request_object', {
        error_description: `could not parse request object as valid JWT (${err.message})`,
      });
    }

    let payload = decoded.payload;

    this.assert(payload.request === undefined &&
      payload.request_uri === undefined, 400, 'invalid_request_object', {
        error_description: 'request object must not contain request or request_uri properties',
      });

    payload = _.pick(payload, PARAM_LIST);

    this.assert(payload.response_type === undefined ||
      payload.response_type === params.response_type, 400,
        'invalid_request_object', {
          error_description: 'request response_type must equal the one in request parameters',
        });

    this.assert(payload.client_id === undefined ||
      payload.client_id === params.client_id, 400, 'invalid_request_object', {
        error_description: 'request client_id must equal the one in request parameters',
      });

    const client = this.oidc.client;
    const alg = decoded.header.alg;

    if (client.requestObjectSigningAlg) {
      this.assert(client.requestObjectSigningAlg === alg, 400,
        'invalid_request_object', {
          error_description: 'the preregistered alg must be used in request or request_uri',
        });
    } else {
      this.assert(conf('requestObjectSigningAlgValues').indexOf(alg) !== -1, 400,
        'invalid_request_object', { error_description: 'unsupported signed request alg' });
    }

    if (alg !== 'none') {
      try {
        yield JWT.verify(params.request, client.keystore);
      } catch (err) {
        this.throw(400, 'invalid_request_object', {
          error_description: `could not validate request object signature (${err.message})`,
        });
      }
    }

    Object.assign(params, payload);
    params.request = undefined;

    yield next;
  };
};
