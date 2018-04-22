const assert = require('assert');

module.exports = function ensureConform(audiences, clientId) {
  assert(Array.isArray(audiences), 'audiences must be an array');

  const value = Array.from(audiences);
  if (!value.includes(clientId)) {
    value.unshift(clientId);
  }

  return value;
};
