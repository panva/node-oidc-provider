'use strict';

const _ = require('lodash');
const JWT = require('../../helpers/jwt');
const PARAM_LIST = require('../../consts/param_list');

/*
 * Decrypts and validates the content of provided request parameter and replaces the parameters
 * provided via OAuth2.0 authorization request with these
 *
 * @throws: invalid_request_object
 */
module.exports = provider => function* decodeRequest(next) {
  const params = this.oidc.params;

  if (params.request === undefined) {
    yield next;
    return;
  }

  let decoded;

  try {
    if (provider.configuration('features.encryption') &&
      params.request.split('.').length === 5) {
      const decrypted = yield JWT.decrypt(params.request, provider.keystore);
      params.request = decrypted.payload.toString('utf8');
    }
    decoded = JWT.decode(params.request);
  } catch (err) {
    this.throw(400, 'invalid_request_object', {
      error_description: `could not parse request_uri as valid JWT (${err.message})`,
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
