'use strict';

module.exports = function getSessionHandler(provider) {
  return function* sessionHandler(next) {
    this.oidc.session = yield provider.Session.get(this);
    yield next;

    if (this.oidc.session.transient) {
      this.response.get('set-cookie').forEach((cookie, index, ary) => {
        if (cookie.startsWith('_session') && !cookie.includes('expires=Thu, 01 Jan 1970')) {
          ary[index] = cookie.replace(/(; ?expires=([\w\d:, ]+))/, '');
        }
      });
    }

    yield this.oidc.session.save();
  };
};
