const setAudiences = require('./mixins/set_audiences');
const hasFormat = require('./mixins/has_format');

module.exports = function getAccessToken(provider) {
  return class AccessToken extends setAudiences(hasFormat(provider, 'AccessToken', provider.BaseToken)) {
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
};
