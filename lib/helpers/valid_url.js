const { URL } = require('url');
const { strict: assert } = require('assert');

module.exports = {
  isHttpsUri(uri) {
    try {
      const { protocol } = new URL(uri);
      assert.strictEqual(protocol, 'https:');
    } catch (err) {
      return false;
    }
    return true;
  },
  isWebUri(uri) {
    try {
      const { protocol } = new URL(uri);
      assert(['https:', 'http:'].includes(protocol));
    } catch (err) {
      return false;
    }
    return true;
  },
};
