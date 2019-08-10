const setAudiences = require('./mixins/set_audiences');
const hasFormat = require('./mixins/has_format');
const isSenderConstrained = require('./mixins/is_sender_constrained');
const apply = require('./mixins/apply');

module.exports = (provider) => class ClientCredentials extends apply([
  setAudiences,
  isSenderConstrained,
  hasFormat(provider, 'ClientCredentials', provider.BaseToken),
]) {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'aud',
      'extra',
      'scope',
    ];
  }
};
