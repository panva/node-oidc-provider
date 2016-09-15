'use strict';

module.exports = function certificatesAction(provider) {
  return function* renderCertificates(next) {
    this.body = provider.keystore.toJSON();

    yield next;
  };
};
