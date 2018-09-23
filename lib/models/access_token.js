const setAudiences = require('./mixins/set_audiences');
const hasFormat = require('./mixins/has_format');
const hasGrantType = require('./mixins/has_grant_type');
const isCertBound = require('./mixins/is_cert_bound');
const apply = require('./mixins/apply');

module.exports = provider => class AccessToken extends apply([
  setAudiences,
  isCertBound,
  hasGrantType,
  hasFormat(provider, 'AccessToken', provider.BaseToken),
]) {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,

      'accountId',
      'claims',
      'grantId',
      'sid',
      'aud',
      'scope',
    ];
  }
};
