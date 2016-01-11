'use strict';

let bufferEqualsConstant = require('buffer-equals-constant');
let errors = require('../helpers/errors');

module.exports = function * tokenCredentialAuth(expected, actual) {
  let valid = bufferEqualsConstant(
    new Buffer(expected, 'utf8'),
    new Buffer(actual, 'utf8'),
    1024
  );

  this.assert(valid, new errors.InvalidClientError(
    'invalid client authentication provided (invalid secret provided)'));
};
