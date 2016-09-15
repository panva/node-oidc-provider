'use strict';

const _ = require('lodash');
const errors = require('../../helpers/errors');

/*
 * Validates presence of mandatory OAuth2.0 parameters response_type, client_id and scope.
 *
 * @throws: invalid_request
 */
module.exports = function* oauthRequired(next) {
  // Validate: required oauth params
  const params = this.oidc.params;
  const missing = _.difference([
    'response_type',
    'client_id',
    'scope',
  ], _.keys(_.omitBy(params, _.isUndefined)));

  this.assert(_.isEmpty(missing), new errors.InvalidRequestError(
    `missing required parameter(s) ${missing.join(',')}`));

  yield next;
};
