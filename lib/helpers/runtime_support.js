const crypto = require('crypto');

const [major, minor] = process.version.substr(1).split('.').map((x) => parseInt(x, 10));

module.exports = {
  'RSA-OAEP-256': major > 12 || (major === 12 && minor >= 9),
  EdDSA: major >= 12,
  KeyObject: typeof crypto.KeyObject !== 'undefined',
};
