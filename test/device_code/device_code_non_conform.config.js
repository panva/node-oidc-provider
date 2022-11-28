const cloneDeep = require('lodash/cloneDeep');

const config = cloneDeep(require('./device_code.config.js'));

config.config.conformIdTokenClaims = false;

module.exports = config;
