const generate = require('nanoid/generate');

module.exports = (charset, mask) => {
  const length = mask.split('*').length - 1;
  const generated = generate(charset, length);
  let at = 0;
  return mask.split('').map((p) => {
    if (p === '*') {
      return generated[at++]; // eslint-disable-line no-plusplus
    }
    return p;
  }).join('');
};
