const assert = require('assert');

const ensureConform = (permissions) => {
  assert(Array.isArray(permissions), 'permissions must be an array');

  const value = permissions.slice();
  value.forEach((permission) => {
    assert(permission && typeof permission === 'string', 'permissions must be non-empty string values');
  });

  return value;
};

module.exports = superclass => class extends superclass {
  setPermissions(permissions) {
    if (permissions) {
      const value = ensureConform(permissions);
      if (value.length) {
        this.perms = value;
      }
    }
  }
};
