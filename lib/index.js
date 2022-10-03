const Provider = require('./provider');
const errors = require('./helpers/errors');

module.exports = Provider;
module.exports.Provider = Provider;
module.exports.errors = errors;
module.exports.interactionPolicy = require('./helpers/interaction_policy');
