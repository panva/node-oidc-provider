const constantEquals = require('buffer-equals-constant');
const errors = require('../helpers/errors');

module.exports = function tokenCredentialAuth(ctx, expected, actual) {
  const valid = constantEquals(new Buffer(expected, 'utf8'), new Buffer(actual, 'utf8'), 1024);

  ctx.assert(valid, new errors.InvalidClientError(
    'invalid client authentication provided (invalid secret provided)'));
};
