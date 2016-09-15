'use strict';

const bodyParser = require('../shared/selective_body');

module.exports = function getConditionalBody(only) {
  const parseBody = bodyParser(only);

  return function* parseBodyIfPost(next) {
    if (this.method === 'POST') {
      yield parseBody.call(this, next);
    } else {
      yield next;
    }
  };
};
