'use strict';

let _ = require('lodash');
let errors = require('../helpers/errors');

module.exports = function * checkDupes(next) {
  let dupParams = _.chain(this.oidc.params).pickBy(Array.isArray).keys().value();

  // Validate: no dup params
  this.assert(_.isEmpty(dupParams),
    new errors.InvalidRequestError(
      `parameters must not be provided twice. ${dupParams.join(',')}`));

  yield next;
};
