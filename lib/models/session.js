/* eslint-disable prefer-rest-params */

const assert = require('assert');

const hash = require('object-hash');

const nanoid = require('../helpers/nanoid');
const epochTime = require('../helpers/epoch_time');
const instance = require('../helpers/weak_cache');

const hasFormat = require('./mixins/has_format');

const NON_REJECTABLE_CLAIMS = new Set(['sub', 'sid', 'auth_time', 'acr', 'amr', 'iss']);
const NON_REJECTABLE_SCOPES = new Set(['openid']);

module.exports = function getSession(provider) {
  function setterSetValidation(values, forbiddenMembers = [], ignoredMembers = []) {
    if (Array.isArray(values)) {
      values = new Set(values); // eslint-disable-line no-param-reassign
    } else if (!(values instanceof Set)) {
      throw new Error('expected Array or Set');
    }

    forbiddenMembers.forEach((forbidden) => {
      if (values.has(forbidden)) {
        throw new Error(`${forbidden} cannot be rejected`);
      }
    });

    ignoredMembers.forEach(Set.prototype.delete.bind(values));

    return [...values];
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

  class Session extends hasFormat(provider, 'Session', instance(provider).BaseModel) {
    constructor(payload) {
      super(payload);
      if (!payload) {
        Object.defineProperty(this, 'new', { value: true });
      }
      this.uid = this.uid || nanoid();
      this.jti = this.jti || nanoid();
    }

    get id() {
      return this.jti;
    }

    set id(value) {
      this.jti = value;
    }

    static get IN_PAYLOAD() {
      return [
        ...super.IN_PAYLOAD,
        'uid',
        'acr',
        'amr',
        'account',
        'loginTs',
        'transient',
        'state',
        'authorizations',
      ];
    }

    static async findByUid(uid) {
      let rethrow;
      try {
        const stored = await this.adapter.findByUid(uid).catch((err) => {
          rethrow = true;
          throw err;
        });
        assert(stored);
        const payload = await this.verify(undefined, stored, {
          foundByReference: true,
        });
        return new this(payload);
      } catch (err) {
        if (rethrow) throw err;
        return undefined;
      }
    }

    static async get(ctx) {
      // is there supposed to be a session bound? generate if not
      const cookieSessionId = ctx.cookies.get(provider.cookieName('session'), {
        signed: instance(provider).configuration('cookies.long.signed'),
      });

      let session;

      if (cookieSessionId) {
        session = await this.find(cookieSessionId);
      }

      if (!session) {
        if (cookieSessionId) {
          // underlying session was removed since we have a session id in cookie, let's assign an
          // empty data so that session.new is not true and cookie will get written even if nothing
          // gets written to it
          session = new this({});
        } else {
          session = new this();
        }
      }

      return session;
    }

    async save(ttl = instance(provider).configuration('cookies.long.maxAge') / 1000) {
      // one by one adapter ops to allow for uid to have a unique index
      if (this.oldId) {
        await this.adapter.destroy(this.oldId);
      }

      const result = await super.save(ttl);

      this.touched = false; // TODO:

      return result;
    }

    async destroy() {
      await super.destroy();
      this.destroyed = true; // TODO:
    }

    async resetIdentifier() {
      this.oldId = this.id;
      this.id = nanoid();
      this.touched = true;
    }

    accountId() {
      return this.account;
    }

    authTime() {
      return this.loginTs;
    }

    past(age) {
      const maxAge = +age;

      if (this.loginTs) {
        return epochTime() - this.loginTs > maxAge;
      }

      return true;
    }

    authorizationFor(clientId) {
      // the call will not set, let's not modify the session object
      if (arguments.length === 1 && !this.authorizations) {
        return {};
      }

      this.authorizations = this.authorizations || {};
      const key = String(clientId);
      if (!this.authorizations[key]) {
        this.authorizations[key] = {};
      }

      return this.authorizations[key];
    }

    stateFor(clientId) {
      return hash(this.authorizationFor(clientId), {
        algorithm: 'sha256',
        ignoreUnknown: true,
        unorderedArrays: true,
        unorderedSets: true,
      });
    }

    sidFor(clientId, value) {
      const authorization = this.authorizationFor(...arguments);

      if (value) {
        authorization.sid = value;
        return undefined;
      }

      return authorization.sid;
    }

    grantIdFor(clientId, value) {
      const authorization = this.authorizationFor(...arguments);

      if (value) {
        authorization.grantId = value;
        return undefined;
      }

      return authorization.grantId;
    }

    metaFor(clientId, value) {
      const authorization = this.authorizationFor(...arguments);

      if (value) {
        authorization.meta = value;
        return undefined;
      }

      return authorization.meta;
    }

    acceptedScopesFor(clientId) {
      const accepted = new Set(this.promptedScopesFor(clientId));
      this.rejectedScopesFor(clientId).forEach(Set.prototype.delete.bind(accepted));
      return accepted;
    }

    acceptedClaimsFor(clientId) {
      const accepted = new Set(this.promptedClaimsFor(clientId));
      this.rejectedScopesFor(clientId).forEach(Set.prototype.delete.bind(accepted));
      return accepted;
    }

    promptedScopesFor(clientId, scopes) {
      const authorization = this.authorizationFor(...arguments);

      if (scopes) {
        if (authorization.promptedScopes) {
          authorization.promptedScopes = [
            ...new Set([
              ...authorization.promptedScopes,
              ...setterSetValidation(scopes),
            ]),
          ];
          return undefined;
        }

        authorization.promptedScopes = setterSetValidation(scopes);
        return undefined;
      }


      return getterSetTransformation(authorization.promptedScopes);
    }

    rejectedScopesFor(clientId, scopes, replace = false) {
      const authorization = this.authorizationFor(...arguments);

      if (scopes) {
        if (replace || !authorization.rejectedScopes) {
          authorization.rejectedScopes = setterSetValidation(scopes, NON_REJECTABLE_SCOPES);
          return undefined;
        }

        authorization.rejectedScopes = [
          ...new Set([
            ...authorization.rejectedScopes,
            ...setterSetValidation(scopes, NON_REJECTABLE_SCOPES),
          ]),
        ];
        return undefined;
      }

      return getterSetTransformation(authorization.rejectedScopes);
    }

    promptedClaimsFor(clientId, claims) {
      const authorization = this.authorizationFor(...arguments);

      if (claims) {
        if (authorization.promptedClaims) {
          authorization.promptedClaims = [
            ...new Set([
              ...authorization.promptedClaims,
              ...setterSetValidation(claims),
            ]),
          ];
          return undefined;
        }

        authorization.promptedClaims = setterSetValidation(claims);
        return undefined;
      }

      return getterSetTransformation(authorization.promptedClaims);
    }

    rejectedClaimsFor(clientId, claims, replace = false) {
      const authorization = this.authorizationFor(...arguments);

      if (claims) {
        if (replace || !authorization.rejectedClaims) {
          authorization.rejectedClaims = setterSetValidation(claims, NON_REJECTABLE_CLAIMS);
          return undefined;
        }

        authorization.rejectedClaims = [
          ...new Set([
            ...authorization.rejectedClaims,
            ...setterSetValidation(claims, NON_REJECTABLE_CLAIMS),
          ]),
        ];
        return undefined;
      }

      return getterSetTransformation(authorization.rejectedClaims);
    }
  }

  return Session;
};
