import apply from './mixins/apply.js';
import consumable from './mixins/consumable.js';
import hasFormat from './mixins/has_format.js';
import hasGrantId from './mixins/has_grant_id.js';

export default (provider) => class PreAuthorizedCode extends apply([
  consumable,
  hasGrantId,
  hasFormat(provider, 'PreAuthorizedCode', provider.BaseToken),
]) {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'accountId',
      'claims',
      'rar',
      'resource',
      'scope',
      'txCode',
    ];
  }
};
