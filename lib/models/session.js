const assert = require('assert');
const { deprecate } = require('util');

const uuid = require('uuid/v4');
const hash = require('object-hash');

const epochTime = require('../helpers/epoch_time');
const instance = require('../helpers/weak_cache');

const deprecated = deprecate(() => {}, 'Session.find returning new sessions if none is found is deprecated');

const NON_REJECTABLE_CLAIMS = new Set(['sub', 'sid', 'auth_time', 'acr', 'amr', 'iss']);
const NON_REJECTABLE_SCOPES = new Set(['openid']);

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

  function setterSetValidation(values, forbiddenMembers) {
    if (values instanceof Set) {
      values = Array.from(values); // eslint-disable-line no-param-reassign
    } else if (!Array.isArray(values)) {
      throw new Error('expected Array or Set');
    }

    if (forbiddenMembers) {
      for (const member of values) { // eslint-disable-line no-restricted-syntax
        if (forbiddenMembers.has(member)) {
          throw new Error(`${member} cannot be rejected`);
        }
      }
    }

    return values;
  }

  function getterSetTransformation(value) {
    if (Array.isArray(value)) {
      return new Set(value);
    }
    if (typeof value === 'undefined') {
      return new Set();
    }
    /* istanbul ignore next */
    throw new Error('expected Array to be stored');
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

    stateFor(clientId) {
      return hash(authorizationFor.call(this, clientId), {
        ignoreUnknown: true,
        unorderedArrays: true,
        unorderedSets: true,
      });
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

    promptedScopesFor(clientId, scopes) {
      const authorization = authorizationFor.call(this, clientId);

      if (scopes) {
        authorization.promptedScopes = setterSetValidation(scopes);
        return undefined;
      }

      return getterSetTransformation(authorization.promptedScopes);
    }

    rejectedScopesFor(clientId, scopes) {
      const authorization = authorizationFor.call(this, clientId);

      if (scopes) {
        authorization.rejectedScopes = setterSetValidation(scopes, NON_REJECTABLE_SCOPES);
        return undefined;
      }

      return getterSetTransformation(authorization.rejectedScopes);
    }

    promptedClaimsFor(clientId, claims) {
      const authorization = authorizationFor.call(this, clientId);

      if (claims) {
        authorization.promptedClaims = setterSetValidation(claims);
        return undefined;
      }

      return getterSetTransformation(authorization.promptedClaims);
    }

    rejectedClaimsFor(clientId, claims) {
      const authorization = authorizationFor.call(this, clientId);

      if (claims) {
        authorization.rejectedClaims = setterSetValidation(claims, NON_REJECTABLE_CLAIMS);
        return undefined;
      }

      return getterSetTransformation(authorization.rejectedClaims);
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
