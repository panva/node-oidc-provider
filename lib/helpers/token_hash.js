'use strict';

const base64url = require('base64url');
const crypto = require('crypto');

module.exports = function tokenHash(token, signingAlg) {
  const match = /\w(\d{3})$/.exec(signingAlg);
  let hashingAlg = 'sha256';

  if (match && match[1] !== '256') {
    hashingAlg = `sha${match[1]}`;
  }

  const leftMost = crypto.createHash(hashingAlg).update(token).digest('hex');
  return base64url(new Buffer(leftMost.slice(0, leftMost.length / 2), 'hex'));
};
