'use strict';

module.exports = function * noCache(next) {
  this.set('Pragma', 'no-cache');
  this.set('Cache-Control', 'no-cache, no-store');
  yield next;
};
