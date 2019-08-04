const { strict: assert } = require('assert');

module.exports = function ensureConform(audience) {
  assert(
    (Array.isArray(audience) || typeof audience === 'string') && audience.length,
    'audiences must be an array with members or a single string value',
  );

  // TODO: in v7.x transform an array with a single member to a string

  let value;
  if (typeof audience === 'string') {
    value = audience;
  } else {
    value = [...audience];
    value.forEach((aud) => {
      assert(typeof aud === 'string' && aud.length, 'audiences must be non-empty string values');
    });
  }

  return value;
};
