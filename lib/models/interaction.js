const instance = require('../helpers/weak_cache');
const epochTime = require('../helpers/epoch_time');

const hasFormat = require('./mixins/has_format');

module.exports = (provider) => class Interaction extends hasFormat(provider, 'Interaction', instance(provider).BaseModel) {
  constructor(jti, payload) {
    if (arguments.length === 2) {
      if (payload.session instanceof instance(provider).BaseModel) {
        const { session } = payload;
        Object.assign(payload, session.accountId ? {
          session: {
            accountId: session.accountId,
            ...(session.uid ? { uid: session.uid } : undefined),
            ...(session.jti ? { cookie: session.jti } : undefined),
            ...(session.acr ? { acr: session.acr } : undefined),
            ...(session.amr ? { amr: session.amr } : undefined),
          },
        } : { session: undefined });
      }

      if (payload.grant instanceof instance(provider).BaseModel) {
        const { grant } = payload;
        if (grant.jti) {
          Object.assign(payload, { grantId: grant.jti });
        }
      }

      super({ jti, ...payload });
    } else {
      super(jti);
    }
  }

  get uid() {
    return this.jti;
  }

  set uid(value) {
    this.jti = value;
  }

  async save(ttl) {
    if (typeof ttl !== 'number') {
      throw new TypeError('"ttl" argument must be a number');
    }
    return super.save(ttl);
  }

  async persist() {
    if (typeof this.exp !== 'number') {
      throw new TypeError('persist can only be called on previously persisted Interactions');
    }
    return this.save(this.exp - epochTime());
  }

  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'session',
      'params',
      'prompt',
      'result',
      'returnTo',
      'trusted',
      'grantId',
      'lastSubmission',
      'deviceCode',
    ];
  }
};
