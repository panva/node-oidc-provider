const cloneDeep = require('lodash/cloneDeep');

const setup = cloneDeep(require('./conform.config'));

setup.config.conformIdTokenClaims = false;

module.exports = setup;
