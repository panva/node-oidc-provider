import setAudience from './mixins/set_audience.js';
import hasFormat from './mixins/has_format.js';
import isSenderConstrained from './mixins/is_sender_constrained.js';
import apply from './mixins/apply.js';

export default (provider) => class ClientCredentials extends apply([
  setAudience,
  isSenderConstrained,
  hasFormat(provider, 'ClientCredentials', provider.BaseToken),
]) {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'aud',
      'extra',
      'scope',
    ];
  }
};
