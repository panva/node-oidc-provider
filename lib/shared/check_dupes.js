'use strict';

const _ = require('lodash');
const errors = require('../helpers/errors');

module.exports = async function checkDupes(ctx, next) {
  const dupes = _.chain(ctx.oidc.params).pickBy(Array.isArray).keys().value();

  // Validate: no dup params
  ctx.assert(_.isEmpty(dupes),
    new errors.InvalidRequestError(`parameters must not be provided twice. ${dupes.join(',')}`));

  await next();
};
