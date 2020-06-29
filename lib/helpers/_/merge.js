/* eslint-disable no-restricted-syntax */

const isPlainObject = require('./is_plain_object');

function merge(...sources) {
  const target = {};
  for (const source of sources) {
    if (!isPlainObject(source)) {
      continue; // eslint-disable-line no-continue
    }
    for (const [key, value] of Object.entries(source)) {
      if (isPlainObject(target[key]) && isPlainObject(value)) {
        target[key] = merge(target[key], value);
      } else if (typeof value !== 'undefined') {
        target[key] = value;
      }
    }
  }

  return target;
}

module.exports = merge.bind(undefined, false);
