'use strict';

const _ = require('lodash');
const cert = require('../default.sig.key');
const config = _.clone(require('../default.config'));

module.exports = {
  config,
  certs: [cert],
};
