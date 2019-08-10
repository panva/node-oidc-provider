const instance = require('../helpers/weak_cache');

const hasFormat = require('./mixins/has_format');

module.exports = (provider) => class Interaction extends hasFormat(provider, 'Interaction', instance(provider).BaseModel) {
  constructor(id, payload) {
    if (arguments.length === 2) {
      super({ ...payload, jti: id });
    } else {
      super(id);
    }
  }

  async save(ttl = instance(provider).configuration('cookies.short.maxAge') / 1000) {
    return super.save(ttl);
  }

  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'session',
      'params',
      'prompt',
      'result',
      'returnTo',
      'signed',
      'uid',
      'lastSubmission',
    ];
  }
};
