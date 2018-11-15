const nanoid = require('./nanoid');

const CHARS = {
  'base-20': 'BCDFGHJKLMNPQRSTVWXZ',
  digits: '0123456789',
};

module.exports.generate = (charset, mask) => {
  const length = mask.split('*').length - 1;
  const generated = nanoid(length, CHARS[charset]);
  let at = 0;
  return mask.split('').map((p) => {
    if (p === '*') {
      return generated[at++]; // eslint-disable-line no-plusplus
    }
    return p;
  }).join('');
};

module.exports.normalize = input => input
  .replace(/[a-z]/g, char => char.toUpperCase())
  .replace(/\W/g, () => '');
