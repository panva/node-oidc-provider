import apply from './mixins/apply.js';
import hasFormat from './mixins/has_format.js';
import hasGrantType from './mixins/has_grant_type.js';
import hasGrantId from './mixins/has_grant_id.js';
import isSenderConstrained from './mixins/is_sender_constrained.js';
import isSessionBound from './mixins/is_session_bound.js';
import setAudience from './mixins/set_audience.js';

export default (provider) => class AccessToken extends apply([
  hasGrantType,
  hasGrantId,
  isSenderConstrained,
  isSessionBound(provider),
  setAudience,
  hasFormat(provider, 'AccessToken', provider.BaseToken),
]) {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,

      'accountId',
      'aud',
      'claims',
      'extra',
      'grantId',
      'scope',
      'sid',
    ];
  }
};
