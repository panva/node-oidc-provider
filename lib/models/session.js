const assert = require('assert');
const { deprecate } = require('util');

const uuid = require('uuid/v4');

const epochTime = require('../helpers/epoch_time');
const instance = require('../helpers/weak_cache');

const deprecated = deprecate(() => {}, 'Session.find returning new sessions if none is found is deprecated');

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

    async save(ttl = instance(provider).configuration('cookies.long.maxAge') / 1000) {
      const payload = { ...this, ...(ttl ? { exp: epochTime() + ttl } : {}) };
      delete payload.id;
      await getAdapter().upsert(this.id, payload, ttl);
      this.touched = false; // TODO:
    }

    async destroy() {
      await getAdapter().destroy(this.id);
      this.destroyed = true; // TODO:
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

    static async find(id, { upsert = true } = {}) {
      assert(id, 'id must be provided to Session#find');
      const data = await getAdapter().find(id);
      if (data) {
        const clockTolerance = instance(provider).configuration('clockTolerance');
        if (data.exp && epochTime() - clockTolerance >= data.exp) {
          await getAdapter().destroy(id);
        } else {
          return new Session(id, data);
        }
      }
      /* istanbul ignore if */
      if (upsert) {
        deprecated();
        return new Session(id);
      }
      return undefined;
    }

    static async get(ctx) {
      // is there supposed to be a session bound? generate if not
      let sessionId = ctx.cookies.get(provider.cookieName('session'), {
        signed: instance(provider).configuration('cookies.long.signed'),
      });

      let session;
      if (sessionId) {
        session = await this.find(sessionId, { upsert: false });
      }
      if (!session) {
        sessionId = uuid();
        session = new this(sessionId);
      }

      // refresh the session duration
      ctx.cookies.set(provider.cookieName('session'), sessionId, instance(provider).configuration('cookies.long'));
      return session;
    }
  }

  return Session;
};
