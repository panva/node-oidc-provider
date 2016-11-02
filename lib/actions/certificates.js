'use strict';

const instance = require('../helpers/weak_cache');

module.exports = function certificatesAction(provider) {
  return function* renderCertificates(next) {
    this.body = instance(provider).keystore.toJSON();

    yield next;
  };
};
