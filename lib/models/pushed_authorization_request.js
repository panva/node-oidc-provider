import instance from '../helpers/weak_cache.js';

import apply from './mixins/apply.js';
import hasFormat from './mixins/has_format.js';
import consumable from './mixins/consumable.js';

export default (provider) => class PushedAuthorizationRequest extends apply([
  consumable,
  hasFormat(provider, 'PushedAuthorizationRequest', instance(provider).BaseModel),
]) {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'request',
      'dpopJkt',
      'trusted',
    ];
  }
};
