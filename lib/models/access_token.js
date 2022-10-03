const apply = require('./mixins/apply');
const hasFormat = require('./mixins/has_format');
const hasGrantType = require('./mixins/has_grant_type');
const hasGrantId = require('./mixins/has_grant_id');
const isSenderConstrained = require('./mixins/is_sender_constrained');
const isSessionBound = require('./mixins/is_session_bound');
const setAudience = require('./mixins/set_audience');

module.exports = (provider) => class AccessToken extends apply([
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
