const { InvalidRequest } = require('./errors');
const _ = require('lodash');

module.exports = function validatePresence(ctx, required) {
  const missing = _.difference(required, _.keys(_.omitBy(ctx.oidc.params, _.isUndefined)));

  if (!_.isEmpty(missing)) {
    ctx.throw(new InvalidRequest(`missing required parameter(s). (${missing.join(',')})`));
  }
};
