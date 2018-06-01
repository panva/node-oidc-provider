const { chain, isUndefined } = require('lodash');

module.exports = function setWWWAuthenticate(ctx, scheme, fields) {
  const wwwAuth = chain(fields).omitBy(isUndefined)
    .map((val, key) => `${key}="${val}"`)
    .value()
    .join(', ');

  ctx.set('WWW-Authenticate', `${scheme} ${wwwAuth}`);
};
