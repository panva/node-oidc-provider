'use strict';

module.exports = function(provider) {
  return function * (next) {
    this.oidc.session = yield provider.Session.get(this);
    yield next;
    yield this.oidc.session.save();
  };
};
