'use strict';

let base64url = require('base64url');
let crypto = require('crypto');

module.exports = function (token, signingAlg) {
  let match = /\w(\d{3})$/.exec(signingAlg);
  let hashingAlg = 'sha256';

  if (match && match[1] !== '256') {
    hashingAlg = `sha${match[1]}`;
  }

  let leftMost = crypto.createHash(hashingAlg).update(token).digest('hex');
  return base64url(new Buffer(leftMost.slice(0, leftMost.length / 2), 'hex'));
};
