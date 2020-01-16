const instance = require('../helpers/weak_cache');

const hasFormat = require('./mixins/has_format');

module.exports = (provider) => class Interaction extends hasFormat(provider, 'Interaction', instance(provider).BaseModel) {
  constructor(id, payload) {
    if (arguments.length === 2) {
      if (payload.session instanceof instance(provider).BaseModel) {
        const { session } = payload;
        const accountId = session.accountId();
        Object.assign(payload, accountId ? {
          session: {
            accountId,
            ...(session.uid ? { uid: session.uid } : undefined),
            ...(session.jti ? { cookie: session.jti } : undefined),
            ...(session.acr ? { acr: session.acr } : undefined),
            ...(session.amr ? { amr: session.amr } : undefined),
          },
        } : { session: undefined });
      }

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
