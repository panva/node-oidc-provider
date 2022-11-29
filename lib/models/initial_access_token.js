import apply from './mixins/apply.js';
import hasFormat from './mixins/has_format.js';
import hasPolicies from './mixins/has_policies.js';

export default (provider) => class InitialAccessToken extends apply([
  hasPolicies(provider),
  hasFormat(provider, 'InitialAccessToken', provider.BaseToken),
]) {
  static get IN_PAYLOAD() {
    return super.IN_PAYLOAD.filter((v) => v !== 'clientId');
  }
};
