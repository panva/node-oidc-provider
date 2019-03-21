const { cloneDeep } = require('lodash');

const config = cloneDeep(require('./device_code.config'));

config.config.conformIdTokenClaims = false;

module.exports = config;
