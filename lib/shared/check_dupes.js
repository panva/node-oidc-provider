const { chain, isEmpty } = require('lodash');
const { InvalidRequest } = require('../helpers/errors');

module.exports = async function checkDupes(ctx, next) {
  const dupes = chain(ctx.oidc.params).pickBy(Array.isArray).keys().value();

  // Validate: no dup params
  if (!isEmpty(dupes)) {
    ctx.throw(new InvalidRequest(`parameters must not be provided twice. ${dupes.join(',')}`));
  }

  await next();
};
