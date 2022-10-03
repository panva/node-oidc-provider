const { strict: assert } = require('assert');
const { timingSafeEqual } = require('crypto');

function paddedBuffer(string, length) {
  const buffer = Buffer.alloc(length, undefined, 'utf8');
  buffer.write(string);
  return buffer;
}

function constantEquals(a, b, minComp = 0) {
  assert(Number.isSafeInteger(minComp), 'minComp must be an Integer');
  assert.equal(typeof a, 'string', 'arguments must be strings');
  assert.equal(typeof b, 'string', 'arguments must be strings');
  const length = Math.max(a.length, b.length, minComp);
  return timingSafeEqual(paddedBuffer(a, length), paddedBuffer(b, length));
}

module.exports = constantEquals;
