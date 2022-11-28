const apply = require('./mixins/apply.js');
const hasFormat = require('./mixins/has_format.js');
const hasGrantType = require('./mixins/has_grant_type.js');
const hasGrantId = require('./mixins/has_grant_id.js');
const isSenderConstrained = require('./mixins/is_sender_constrained.js');
const isSessionBound = require('./mixins/is_session_bound.js');
const setAudience = require('./mixins/set_audience.js');

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
