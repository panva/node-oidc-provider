const { strict: assert } = require('assert');

const omitBy = require('./_/omit_by');

const cache = new WeakMap();

module.exports = function getParams(allowList) {
  if (!cache.has(allowList)) {
    assert(allowList, 'allowList must be present');

    const klass = class Params {
      constructor(params) {
        allowList.forEach((prop) => {
          this[prop] = params[prop] || undefined;
        });
      }

      toPlainObject() {
        return omitBy({ ...this }, (val) => typeof val === 'undefined');
      }
    };

    cache.set(allowList, klass);
  }

  return cache.get(allowList);
};
