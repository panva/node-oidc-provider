'use strict';

module.exports = function getSessionHandler(provider) {
  return function * sessionHandler(next) {
    this.oidc.session = yield provider.Session.get(this);
    yield next;
    yield this.oidc.session.save();
  };
};
