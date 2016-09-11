'use strict';

const errors = require('./errors');
const _ = require('lodash');

module.exports = function validatePresence(required) {
  const missing = _.difference(required, _.keys(_.omitBy(this.oidc.params, _.isUndefined)));

  this.assert(_.isEmpty(missing), new errors.InvalidRequestError(
    `missing required parameter(s). (${missing.join(',')})`));
};
