const setAudiences = require('./mixins/set_audiences');
const hasFormat = require('./mixins/has_format');
const apply = require('./mixins/apply');

module.exports = provider => class AccessToken extends apply([
  setAudiences,
  hasFormat(provider, 'AccessToken', provider.BaseToken),
]) {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,

      'accountId',
      'claims',
      'grantId',
      'aud',
      'scope',
    ];
  }
};
