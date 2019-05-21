const assert = require('assert');

const { omitBy, isUndefined } = require('lodash');

const cache = new WeakMap();

module.exports = function getParams(whitelist) {
  if (!cache.has(whitelist)) {
    assert(whitelist, 'whitelist must be present');

    const klass = class Params {
      constructor(params) {
        whitelist.forEach((prop) => { this[prop] = params[prop]; });
      }

      toPlainObject() {
        return omitBy(this, isUndefined);
      }
    };

    cache.set(whitelist, klass);
  }

  return cache.get(whitelist);
};
