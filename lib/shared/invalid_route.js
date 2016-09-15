'use strict';

const errors = require('../helpers/errors');

module.exports = function* invalidRoute(next) {
  yield next;
  if (this.status === 404 && this.message === 'Not Found') {
    this.throw(new errors.InvalidRequestError('unrecognized route', 404));
  }
};
