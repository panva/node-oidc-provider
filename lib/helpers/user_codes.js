const nanoid = require('./nanoid');

const CHARS = {
  'base-20': 'BCDFGHJKLMNPQRSTVWXZ',
  digits: '0123456789',
};

module.exports.generate = (charset, mask) => {
  const length = mask.split('*').length - 1;
  const generated = nanoid(length, CHARS[charset]).split('');
  return mask.split('').map((p) => {
    if (p === '*') {
      return generated.shift();
    }

    return p;
  }).join('');
};

module.exports.denormalize = (normalized, mask) => {
  const chars = normalized.split('');
  return mask.split('').map((p) => {
    if (p === '*') {
      return chars.shift();
    }

    return p;
  }).join('');
};

module.exports.normalize = (input) => input
  .replace(/[a-z]/g, (char) => char.toUpperCase())
  .replace(/\W/g, () => '');
