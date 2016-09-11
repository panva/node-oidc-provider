'use strict';

const base64url = require('base64url');
const crypto = require('crypto');

module.exports = function tokenHash(token, signingAlg) {
  const size = String(signingAlg).slice(-3);
  let hashingAlg;

  switch (size) {
    case '512':
      hashingAlg = 'sha512';
      break;
    case '384':
      hashingAlg = 'sha384';
      break;
    default:
      hashingAlg = 'sha256';
  }

  const digest = crypto.createHash(hashingAlg).update(token).digest('hex');
  return base64url(new Buffer(digest.slice(0, digest.length / 2), 'hex'));
};
