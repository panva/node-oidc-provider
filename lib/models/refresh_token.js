const storesAuth = require('./mixins/stores_auth');
const hasFormat = require('./mixins/has_format');
const consumable = require('./mixins/consumable');
const apply = require('./mixins/apply');

module.exports = provider => class RefreshToken extends apply([
  consumable,
  storesAuth,
  hasFormat(provider, 'RefreshToken', provider.BaseToken),
]) {};
