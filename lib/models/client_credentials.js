const setAudience = require('./mixins/set_audience.js');
const hasFormat = require('./mixins/has_format.js');
const isSenderConstrained = require('./mixins/is_sender_constrained.js');
const apply = require('./mixins/apply.js');

module.exports = (provider) => class ClientCredentials extends apply([
  setAudience,
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
