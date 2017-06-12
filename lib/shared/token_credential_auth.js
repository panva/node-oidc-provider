const constantEquals = require('buffer-equals-constant');
const { InvalidClientError } = require('../helpers/errors');

module.exports = function tokenCredentialAuth(ctx, expected, actual) {
  const valid = constantEquals(new Buffer(expected, 'utf8'), new Buffer(actual, 'utf8'), 1024);

  if (!valid) {
    ctx.throw(new InvalidClientError(
      'invalid client authentication provided (invalid secret provided)'));
  }
};
