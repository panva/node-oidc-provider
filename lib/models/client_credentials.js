const setAudiences = require('./mixins/set_audiences');
const hasFormat = require('./mixins/has_format');

module.exports = function getClientCredentials(provider) {
  return class ClientCredentials extends setAudiences(hasFormat(provider, 'ClientCredentials', provider.BaseToken)) {
    static get IN_PAYLOAD() {
      return [
        ...super.IN_PAYLOAD,
        'aud',
        'scope',
      ];
    }
  };
};
