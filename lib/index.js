const Provider = require('./provider');
const errors = require('./helpers/errors');
const { DYNAMIC_SCOPE_LABEL } = require('./consts');

module.exports = Provider;
module.exports.errors = errors;
module.exports.DYNAMIC_SCOPE_LABEL = DYNAMIC_SCOPE_LABEL;
module.exports.interactionPolicy = require('./helpers/interaction_policy');
