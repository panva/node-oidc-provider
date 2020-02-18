const crypto = require('crypto');

const [major, minor] = process.version.substr(1).split('.').map((x) => parseInt(x, 10));
const xofOutputLength = major > 12 || (major === 12 && minor >= 8);
const shake256 = xofOutputLength && crypto.getHashes().includes('shake256');

module.exports = {
  oaepHash: major > 12 || (major === 12 && minor >= 9),
  EdDSA: major >= 12,
  KeyObject: typeof crypto.KeyObject !== 'undefined',
  shake256,
};
