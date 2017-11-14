const constantEquals = require('../helpers/constant_equals');
const { InvalidClientError } = require('../helpers/errors');

module.exports = function tokenCredentialAuth(ctx, expected, actual) {
  if (!constantEquals(expected, actual, 1000)) {
    ctx.throw(new InvalidClientError('invalid client authentication provided (invalid secret provided)'));
  }
};
