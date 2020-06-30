/* eslint-disable prefer-rest-params */

const { strict: assert } = require('assert');

const hash = require('object-hash');

const nanoid = require('../helpers/nanoid');
const epochTime = require('../helpers/epoch_time');
const instance = require('../helpers/weak_cache');
const base64url = require('../helpers/base64url');
const ssHandler = require('../helpers/samesite_handler');

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
      const stored = await this.adapter.findByUid(uid);
      try {
        assert(stored);
        const payload = await this.verify(undefined, stored, { foundByReference: true });
        return new this(payload);
      } catch (err) {
        return undefined;
      }
    }

    static async get(ctx) {
      const cookies = ctx.oidc
        ? ctx.oidc.cookies : provider.app.createContext(ctx.req, ctx.res).cookies;
      cookies.secure = !cookies.secure && ctx.secure ? true : cookies.secure;

      // is there supposed to be a session bound? generate if not
      const cookieSessionId = ssHandler.get(
        cookies,
        provider.cookieName('session'),
        instance(provider).configuration('cookies.long'),
      );

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

      if (ctx.oidc instanceof provider.OIDCContext) {
        ctx.oidc.entity('Session', session);
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

    resetIdentifier() {
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
      if (!this.authorizations[clientId]) {
        this.authorizations[clientId] = {};
      }

      return this.authorizations[clientId];
    }

    stateFor(clientId) {
      return base64url.encodeBuffer(hash(this.authorizationFor(clientId), {
        algorithm: 'sha256',
        ignoreUnknown: true,
        unorderedArrays: true,
        unorderedSets: true,
        encoding: 'buffer',
      }));
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
      this.rejectedClaimsFor(clientId).forEach(Set.prototype.delete.bind(accepted));
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

    ensureClientContainer(clientId) {
      if (!this.sidFor(clientId)) {
        this.sidFor(clientId, nanoid());
      }

      if (!this.grantIdFor(clientId)) {
        this.grantIdFor(clientId, nanoid());
      }
    }

    loginAccount(details) {
      const {
        transient = false, account, loginTs = epochTime(), amr, acr,
      } = details;

      Object.assign(
        this,
        {
          account, loginTs, amr, acr,
        },
        transient ? { transient: true } : undefined,
      );
    }
  }

  return Session;
};
