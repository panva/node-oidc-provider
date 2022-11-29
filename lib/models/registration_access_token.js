import apply from './mixins/apply.js';
import hasFormat from './mixins/has_format.js';
import hasPolicies from './mixins/has_policies.js';

export default (provider) => class RegistrationAccessToken extends apply([
  hasPolicies(provider),
  hasFormat(provider, 'RegistrationAccessToken', provider.BaseToken),
]) {};
