'use strict';

const config = require('../default.config');
const cert = require('../default.sig.key');

module.exports = {
  config,
  clients: [],
  certs: [cert],
};
