const uuid = require('uuid/v4');
const epochTime = require('../helpers/epoch_time');
const assert = require('assert');
const instance = require('../helpers/weak_cache');

module.exports = function getSession(provider) {
  let adapter;

  function getAdapter() {
    if (!adapter) adapter = new (instance(provider).Adapter)('Session');
    return adapter;
  }

  function authorizationFor(clientId) {
    this.authorizations = this.authorizations || {};
    const key = String(clientId);
    if (!this.authorizations[key]) {
      this.authorizations[key] = {};
    }

    return this.authorizations[key];
  }

  class Session {
    constructor(id, data) {
      if (data) Object.assign(this, data);
      this.id = id;
    }

    accountId() {
      return this.account;
    }

    authTime() {
      return this.loginTs;
    }

    past(age) {
      const maxAge = +age;

      if (this.loginTs && Number.isFinite(maxAge) && maxAge > 0) {
        return epochTime() - this.loginTs > maxAge;
      }

      return false;
    }

    save(ttl = instance(provider).configuration('cookies.long.maxAge') / 1000) {
      const payload = Object.assign({}, this, { exp: epochTime() + ttl });
      delete payload.id;

      return getAdapter().upsert(this.id, payload, ttl);
    }

    destroy() {
      return getAdapter().destroy(this.id);
    }

    sidFor(clientId, value) {
      const authorization = authorizationFor.call(this, clientId);

      if (value) {
        authorization.sid = value;
        return undefined;
      }

      return authorization.sid;
    }

    metaFor(clientId, value) {
      const authorization = authorizationFor.call(this, clientId);

      if (value) {
        authorization.meta = value;
        return undefined;
      }

      return authorization.meta;
    }

    static async find(id) {
      assert(id, 'id must be provided to Session#find');
      const data = await getAdapter().find(id);
      if (data && data.exp && data.exp > epochTime()) {
        return new Session(id, data);
      }
      return new Session(id);
    }

    static async get(ctx) {
      // is there supposed to be a session bound? generate if not
      const sessionId = ctx.cookies.get(provider.cookieName('session'), {
        signed: instance(provider).configuration('cookies.long.signed'),
      }) || uuid();

      const session = await this.find(sessionId);

      // refresh the session duration
      ctx.cookies.set(provider.cookieName('session'), sessionId, instance(provider).configuration('cookies.long'));
      return session;
    }
  }

  return Session;
};
