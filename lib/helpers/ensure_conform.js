const assert = require('assert');

module.exports = function ensureConform(audiences, clientId) {
  assert(Array.isArray(audiences), 'audiences must be an array');

  const value = audiences.slice();
  value.forEach((audience) => {
    assert(audience && typeof audience === 'string', 'audiences must be non-empty string values');
  });

  if (clientId && !value.includes(clientId)) {
    value.unshift(clientId);
  }

  return value;
};
