const { clone } = require('lodash');

const setup = clone(require('./conform.config'));

setup.config.conformIdTokenClaims = false;

module.exports = setup;
