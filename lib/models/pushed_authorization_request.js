import instance from '../helpers/weak_cache.js';

import hasFormat from './mixins/has_format.js';

export default (provider) => class PushedAuthorizationRequest extends hasFormat(provider, 'PushedAuthorizationRequest', instance(provider).BaseModel) {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'request',
      'dpopJkt',
      'trusted',
    ];
  }
};
