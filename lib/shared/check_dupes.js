const { chain, isEmpty } = require('lodash');
const { InvalidRequestError } = require('../helpers/errors');

module.exports = async function checkDupes(ctx, next) {
  const dupes = chain(ctx.oidc.params).pickBy(Array.isArray).keys().value();

  // Validate: no dup params
  if (!isEmpty(dupes)) {
    ctx.throw(new InvalidRequestError(`parameters must not be provided twice. ${dupes.join(',')}`));
  }

  await next();
};
