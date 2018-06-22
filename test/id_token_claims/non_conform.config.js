const { clone } = require('lodash');

const setup = clone(require('./conform.config'));

setup.config.features.conformIdTokenClaims = false;

module.exports = setup;
