const constantEquals = require('../helpers/constant_equals');
const { InvalidClientAuth } = require('../helpers/errors');

module.exports = function tokenCredentialAuth(ctx, expected, actual) {
  if (!constantEquals(expected, actual, 1000)) {
    ctx.throw(new InvalidClientAuth('invalid secret provided'));
  }
};
