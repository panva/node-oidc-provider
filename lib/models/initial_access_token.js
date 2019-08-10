const apply = require('./mixins/apply');
const hasFormat = require('./mixins/has_format');
const hasPolicies = require('./mixins/has_policies');

module.exports = (provider) => class InitialAccessToken extends apply([
  hasPolicies(provider),
  hasFormat(provider, 'InitialAccessToken', provider.BaseToken),
]) {
  static get IN_PAYLOAD() {
    return super.IN_PAYLOAD.filter((v) => v !== 'clientId');
  }
};
