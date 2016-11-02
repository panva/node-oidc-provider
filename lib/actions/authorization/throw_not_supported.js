'use strict';

const errors = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');

/*
 * Validates parameters that rely features that are not supported by the provider configuration
 * are not provided and that request and request_uri are not used in conjunction.
 *
 * @throws: invalid_request
 * @throws: request_not_supported
 * @throws: request_uri_not_supported
 * @throws: registration_not_supported
 */
module.exports = provider => function* throwNotSupported(next) {
  const params = this.oidc.params;
  const feature = instance(provider).configuration('features');

  if (!feature.request && params.request !== undefined) {
    this.throw(400, 'request_not_supported', {
      error_description: 'request parameter provided but not supported',
    });
  }

  if (!feature.requestUri && params.request_uri !== undefined) {
    this.throw(400, 'request_uri_not_supported', {
      error_description: 'request_uri parameter provided but not supported',
    });
  }

  if (params.registration !== undefined) {
    this.throw(400, 'registration_not_supported', {
      error_description: 'registration parameter provided but not supported',
    });
  }

  this.assert(params.request === undefined ||
    params.request_uri === undefined, new errors.InvalidRequestError(
      'request and request_uri parameters MUST NOT be used together'));

  yield next;
};
