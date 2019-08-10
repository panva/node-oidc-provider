const apply = require('./mixins/apply');
const hasFormat = require('./mixins/has_format');
const hasPolicies = require('./mixins/has_policies');

module.exports = (provider) => class RegistrationAccessToken extends apply([
  hasPolicies(provider),
  hasFormat(provider, 'RegistrationAccessToken', provider.BaseToken),
]) {};
