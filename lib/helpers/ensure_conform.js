const assert = require('assert');

module.exports = function ensureConform(audiences) {
  assert(Array.isArray(audiences) && audiences.length, 'audiences must be an array with members');

  const value = audiences.slice();
  value.forEach((audience) => {
    assert(audience && typeof audience === 'string', 'audiences must be non-empty string values');
  });

  return value;
};
