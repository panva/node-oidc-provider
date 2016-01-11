'use strict';

let errors = require('./errors');
let _ = require('lodash');

module.exports = function validatePresence(required) {
  let missing = _.difference(required, _.keys(this.oidc.params));

  this.assert(_.isEmpty(missing),
    new errors.InvalidRequestError(
      `missing required parameter(s). (${missing.join(',')})`));
};
