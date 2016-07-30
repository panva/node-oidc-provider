'use strict';

module.exports = function * noCache(next) {
  this.set('Pragma', 'no-cache');
  this.set('cache-control', 'no-store');
  yield next;
};
