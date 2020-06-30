/* eslint-disable no-restricted-syntax */

const isPlainObject = require('./is_plain_object');

function defaults(deep, target, ...sources) {
  for (const source of sources) {
    if (!isPlainObject(source)) {
      continue; // eslint-disable-line no-continue
    }
    for (const [key, value] of Object.entries(source)) {
      if (typeof target[key] === 'undefined' && typeof value !== 'undefined') {
        target[key] = value; // eslint-disable-line no-param-reassign
      }

      if (deep && isPlainObject(target[key]) && isPlainObject(value)) {
        defaults(true, target[key], value);
      }
    }
  }

  return target;
}

module.exports = defaults.bind(undefined, false);
module.exports.deep = defaults.bind(undefined, true);
