const assert = require('assert');

const { omitBy, isUndefined } = require('lodash');

module.exports = function getParams(whitelist) {
  assert(whitelist, 'whitelist must be present');

  return class Params {
    constructor(params) {
      whitelist.forEach((prop) => { this[prop] = params[prop]; });
    }

    toPlainObject() {
      return omitBy(this, isUndefined);
    }
  };
};
