'use strict';

const _ = require('lodash');
const errors = require('../helpers/errors');

module.exports = function * checkDupes(next) {
  const dupes = _.chain(this.oidc.params)
    .pickBy(Array.isArray)
    .keys()
    .value();

  // Validate: no dup params
  this.assert(_.isEmpty(dupes),
    new errors.InvalidRequestError(`parameters must not be provided twice. ${dupes.join(',')}`));

  yield next;
};
