'use strict';

module.exports = function(provider) {

  return function * renderCertificates(next) {

    this.body = provider.keystore.toJSON();

    yield next;
  };
};
