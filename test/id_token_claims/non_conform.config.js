const clone = require('lodash/clone');

const setup = clone(require('./conform.config'));

setup.config.conformIdTokenClaims = false;

module.exports = setup;
