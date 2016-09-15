'use strict';

const _ = require('lodash');
const config = _.clone(require('../default.config'));

config.features = { registration: true };

module.exports = {
  config
};
