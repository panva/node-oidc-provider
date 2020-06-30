/* eslint-disable no-restricted-syntax, no-param-reassign */

const isPlainObject = require('./is_plain_object');

function merge(target, ...sources) {
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

module.exports = merge;
