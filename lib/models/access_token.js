const apply = require('./mixins/apply');
const hasFormat = require('./mixins/has_format');
const hasGrantType = require('./mixins/has_grant_type');
const hasGrantId = require('./mixins/has_grant_id');
const isCertBound = require('./mixins/is_cert_bound');
const isSessionBound = require('./mixins/is_session_bound');
const setAudiences = require('./mixins/set_audiences');

module.exports = provider => class AccessToken extends apply([
  hasGrantType,
  hasGrantId,
  isCertBound,
  isSessionBound(provider),
  setAudiences,
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
