const apply = require('./mixins/apply.js');
const hasFormat = require('./mixins/has_format.js');
const hasPolicies = require('./mixins/has_policies.js');

module.exports = (provider) => class RegistrationAccessToken extends apply([
  hasPolicies(provider),
  hasFormat(provider, 'RegistrationAccessToken', provider.BaseToken),
]) {};
