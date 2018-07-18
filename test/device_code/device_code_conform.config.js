const { cloneDeep } = require('lodash');

const config = cloneDeep(require('./device_code.config'));

config.config.features.conformIdTokenClaims = true;

module.exports = config;
