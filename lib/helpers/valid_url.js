const { URL } = require('url');
const { equal, ok } = require('assert');

module.exports = {
  isHttpsUri(uri) {
    try {
      const { protocol } = new URL(uri);
      equal(protocol, 'https:');
    } catch (err) {
      return false;
    }
    return true;
  },
  isWebUri(uri) {
    try {
      const { protocol } = new URL(uri);
      ok(['https:', 'http:'].includes(protocol));
    } catch (err) {
      return false;
    }
    return true;
  },
};
