const apply = require('./mixins/apply');
const consumable = require('./mixins/consumable');
const hasFormat = require('./mixins/has_format');
const hasGrantType = require('./mixins/has_grant_type');
const storesAuth = require('./mixins/stores_auth');

module.exports = provider => class RefreshToken extends apply([
  consumable(provider),
  storesAuth,
  hasGrantType,
  hasFormat(provider, 'RefreshToken', provider.BaseToken),
]) {};
