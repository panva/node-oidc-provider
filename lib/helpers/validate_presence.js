'use strict';

const errors = require('./errors');
const _ = require('lodash');

module.exports = function validatePresence(required) {
  const missing = _.difference(required, _.keys(this.oidc.params));

  this.assert(_.isEmpty(missing),
    new errors.InvalidRequestError(
      `missing required parameter(s). (${missing.join(',')})`));
};
