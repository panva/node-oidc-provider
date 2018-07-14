const storesAuth = require('./mixins/stores_auth');
const hasFormat = require('./mixins/has_format');
const consumable = require('./mixins/consumable');
const hasGrantType = require('./mixins/has_grant_type');
const apply = require('./mixins/apply');

module.exports = provider => class RefreshToken extends apply([
  consumable(provider),
  storesAuth,
  hasGrantType,
  hasFormat(provider, 'RefreshToken', provider.BaseToken),
]) {};
