const instance = require('../helpers/weak_cache.js');

const hasFormat = require('./mixins/has_format.js');

module.exports = (provider) => class PushedAuthorizationRequest extends hasFormat(provider, 'PushedAuthorizationRequest', instance(provider).BaseModel) {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'request',
      'dpopJkt',
    ];
  }
};
