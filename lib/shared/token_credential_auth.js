const constantEquals = require('../helpers/constant_equals');
const { InvalidClientAuthError } = require('../helpers/errors');

module.exports = function tokenCredentialAuth(ctx, expected, actual) {
  if (!constantEquals(expected, actual, 1000)) {
    ctx.throw(new InvalidClientAuthError('invalid secret provided'));
  }
};
