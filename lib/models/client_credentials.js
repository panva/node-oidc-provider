const setAudiences = require('./mixins/set_audiences');
const setPermissions = require('./mixins/set_permissions');
const hasFormat = require('./mixins/has_format');
const apply = require('./mixins/apply');

module.exports = provider => class ClientCredentials extends apply([
  setAudiences,
  setPermissions,
  hasFormat(provider, 'ClientCredentials', provider.BaseToken),
]) {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'aud',
      'perms',
      'scope',
    ];
  }
};
