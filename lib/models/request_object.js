const instance = require('../helpers/weak_cache');

const hasFormat = require('./mixins/has_format');

module.exports = (provider) => class RequestObject extends hasFormat(provider, 'RequestObject', instance(provider).BaseModel) {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'request',
    ];
  }
};
