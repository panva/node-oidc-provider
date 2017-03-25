'use strict';

const errors = require('./errors');
const _ = require('lodash');

module.exports = function validatePresence(ctx, required) {
  const missing = _.difference(required, _.keys(_.omitBy(ctx.oidc.params, _.isUndefined)));

  ctx.assert(_.isEmpty(missing), new errors.InvalidRequestError(
    `missing required parameter(s). (${missing.join(',')})`));
};
