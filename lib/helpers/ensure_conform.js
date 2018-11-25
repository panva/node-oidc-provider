const assert = require('assert');
const { deprecate } = require('util');

const deprecated = deprecate(() => {}, 'multiple audiences for ID Tokens are deprecated and will be removed in the next major version');

module.exports = function ensureConform(audiences, clientId) {
  assert(Array.isArray(audiences), 'audiences must be an array');

  const value = audiences.slice();
  value.forEach((audience) => {
    assert(audience && typeof audience === 'string', 'audiences must be non-empty string values');
  });

  if (clientId && !value.includes(clientId)) {
    deprecated();
    value.unshift(clientId);
  }

  return value;
};
