'use strict';

const assert = require('assert');
const bodyMw = require('koa-body');
const errors = require('../helpers/errors');

module.exports = function getSelectiveBody(only) {
  assert(only, 'only must be provided');
  const bodyParser = bodyMw({ jsonLimit: '56kb', formLimit: '56kb' });

  return function* selectiveBody(next) {
    if (this.is(only)) {
      yield bodyParser.call(this, next);
    } else {
      const msg = `only ${only} content-type ${this.method} bodies are supported`;
      this.throw(new errors.InvalidRequestError(msg));
    }
  };
};
