const constantEquals = require('../helpers/constant_equals');
const { InvalidClientAuth } = require('../helpers/errors');

module.exports = function tokenCredentialAuth(ctx, actual, expected) {
  if (!constantEquals(expected, actual, 1000)) {
    throw new InvalidClientAuth('invalid secret provided');
  }
};
