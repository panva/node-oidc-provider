const apply = require('./mixins/apply');
const consumable = require('./mixins/consumable');
const hasFormat = require('./mixins/has_format');
const hasGrantId = require('./mixins/has_grant_id');
const hasGrantType = require('./mixins/has_grant_type');
const isCertBound = require('./mixins/is_cert_bound');
const isSessionBound = require('./mixins/is_session_bound');
const storesAuth = require('./mixins/stores_auth');

module.exports = provider => class RefreshToken extends apply([
  consumable,
  hasGrantType,
  hasGrantId,
  isCertBound,
  isSessionBound(provider),
  storesAuth,
  hasFormat(provider, 'RefreshToken', provider.BaseToken),
]) {};
