'use strict';

module.exports = function getSessionHandler(provider) {
  return function* sessionHandler(next) {
    this.oidc.session = yield provider.Session.get(this);
    yield next;

    if (this.oidc.session.transient) {
      this.response.get('set-cookie').forEach((cookie, index, ary) => {
        if (cookie.startsWith(provider.cookieName('session')) && !cookie.includes('expires=Thu, 01 Jan 1970')) {
          ary[index] = cookie.replace(/(; ?expires=([\w\d:, ]+))/, ''); // eslint-disable-line no-param-reassign
        }
      });
    }

    yield this.oidc.session.save();
  };
};
