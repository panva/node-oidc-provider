const { strict: assert } = require('assert');

const omitBy = require('./_/omit_by');

const cache = new WeakMap();

module.exports = function getParams(whitelist) {
  if (!cache.has(whitelist)) {
    assert(whitelist, 'whitelist must be present');

    const klass = class Params {
      constructor(params) {
        whitelist.forEach((prop) => {
          this[prop] = params[prop] || undefined;
        });
      }

      toPlainObject() {
        return omitBy({ ...this }, (val) => typeof val === 'undefined');
      }
    };

    cache.set(whitelist, klass);
  }

  return cache.get(whitelist);
};
