const setAudiences = require('./mixins/set_audiences');

module.exports = function getClientCredentials({ BaseToken }) {
  return class ClientCredentials extends setAudiences(BaseToken) {
    static get IN_PAYLOAD() {
      return [
        ...super.IN_PAYLOAD,
        'aud',
        'scope',
      ];
    }
  };
};
