const instance = require('../helpers/weak_cache');

const hasFormat = require('./mixins/has_format');

module.exports = (provider) => class PushedAuthorizationRequest extends hasFormat(provider, 'PushedAuthorizationRequest', instance(provider).BaseModel) {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'request',
    ];
  }
};
