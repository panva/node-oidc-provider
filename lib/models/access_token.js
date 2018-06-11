const setAudiences = require('./mixins/set_audiences');

module.exports = function getAccessToken({ BaseToken }) {
  return class AccessToken extends setAudiences(BaseToken) {
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
