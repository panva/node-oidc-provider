/* eslint-disable no-unused-expressions */
/* eslint-disable no-param-reassign */

import apply from './mixins/apply.js';
import hasFormat from './mixins/has_format.js';

const NON_REJECTABLE_CLAIMS = new Set(['sub', 'sid', 'auth_time', 'acr', 'amr', 'iss']);

export default (provider) => class Grant extends apply([
  hasFormat(provider, 'Grant', provider.BaseToken),
]) {
  static get IN_PAYLOAD() {
    return [
      'accountId',
      'clientId',
      'resources',
      'openid',
      'rejected',
      ...super.IN_PAYLOAD,
    ];
  }

  clean() {
    if (
      this.openid
      && (!this.openid.scope && (!this.openid.claims || this.openid.claims.length === 0))
    ) {
      delete this.openid;
    }

    if (this.resources) {
      for (const [identifier, value] of Object.entries(this.resources)) {
        if (!value) {
          delete this.resources[identifier];
        }
      }
      if (Object.keys(this.resources).length === 0) {
        delete this.resources;
      }
    }
  }

  async save(...args) {
    this.clean();
    if (this.rejected) this.clean.call(this.rejected);

    return super.save(...args);
  }

  getOIDCScope() {
    if (this.openid?.scope) {
      if (this.rejected) {
        const rejected = this.getOIDCScope.call(this.rejected).split(' ');
        const granted = new Set(this.openid.scope.split(' '));
        for (const scope of rejected) {
          if (scope !== 'openid') {
            granted.delete(scope);
          }
        }
        return [...granted].join(' ');
      }
      return this.openid.scope;
    }
    return '';
  }

  getRejectedOIDCScope() {
    this.rejected ||= {};
    return this.getOIDCScope.call(this.rejected);
  }

  getOIDCScopeFiltered(filter) {
    if (Array.isArray(filter)) {
      filter = new Set(filter);
    } else if (!(filter instanceof Set)) {
      throw new TypeError('"filter" must be an instance of Set');
    }
    const granted = this.getOIDCScope().split(' ');
    return granted.filter(Set.prototype.has.bind(filter)).join(' ');
  }

  addOIDCScope(scope) {
    if (scope instanceof Set) {
      scope = [...scope].join(' ');
    } else if (Array.isArray(scope)) {
      scope = scope.join(' ');
    } else if (typeof scope !== 'string') {
      throw new TypeError('"scope" must be a string');
    }
    this.openid ||= {};
    if (this.openid.scope) {
      this.openid.scope = [...new Set([...this.openid.scope.split(' '), ...scope.split(' ')])].join(' ');
    } else {
      this.openid.scope = scope;
    }
  }

  rejectOIDCScope(...args) {
    this.rejected ||= {};
    this.addOIDCScope.call(this.rejected, ...args);
  }

  getOIDCScopeEncountered() {
    const granted = this.getOIDCScope().split(' ');
    const rejected = this.getRejectedOIDCScope().split(' ');
    return granted.concat(rejected).join(' ');
  }

  getResourceScope(resource) {
    if (typeof resource !== 'string') {
      throw new TypeError('"resource" must be a string');
    }
    if (this.resources?.[resource]) {
      if (this.rejected) {
        const rejected = this.getResourceScope.call(this.rejected, resource).split(' ');
        const granted = new Set(this.resources[resource].split(' '));
        for (const scope of rejected) {
          granted.delete(scope);
        }
        return [...granted].join(' ');
      }
      return this.resources[resource];
    }
    return '';
  }

  getRejectedResourceScope(...args) {
    this.rejected ||= {};
    return this.getResourceScope.call(this.rejected, ...args);
  }

  getResourceScopeFiltered(resource, filter) {
    if (typeof resource !== 'string') {
      throw new TypeError('"resource" must be a string');
    }
    if (Array.isArray(filter)) {
      filter = new Set(filter);
    } else if (!(filter instanceof Set)) {
      throw new TypeError('"filter" must be an instance of Set');
    }
    const granted = this.getResourceScope(resource).split(' ');
    return granted.filter(Set.prototype.has.bind(filter)).join(' ');
  }

  addResourceScope(resource, scope) {
    if (typeof resource !== 'string') {
      throw new TypeError('"resource" must be a string');
    }
    if (scope instanceof Set) {
      scope = [...scope].join(' ');
    } else if (Array.isArray(scope)) {
      scope = scope.join(' ');
    } else if (typeof scope !== 'string') {
      throw new TypeError('"scope" must be a string');
    }
    this.resources ||= {};
    if (this.resources[resource]) {
      this.resources[resource] = [...new Set([...this.resources[resource].split(' '), ...scope.split(' ')])].join(' ');
    } else {
      this.resources[resource] = scope;
    }
  }

  rejectResourceScope(...args) {
    this.rejected ||= {};
    this.addResourceScope.call(this.rejected, ...args);
  }

  getResourceScopeEncountered(resource) {
    if (typeof resource !== 'string') {
      throw new TypeError('"resource" must be a string');
    }
    const granted = this.getResourceScope(resource).split(' ');
    const rejected = this.getRejectedResourceScope(resource).split(' ');
    return granted.concat(rejected).join(' ');
  }

  getOIDCClaims() {
    if (this.openid?.claims) {
      if (this.rejected) {
        const rejected = this.getOIDCClaims.call(this.rejected);
        const granted = new Set(this.openid.claims);
        for (const claim of rejected) {
          if (!NON_REJECTABLE_CLAIMS.has(claim)) {
            granted.delete(claim);
          }
        }
        return [...granted];
      }
      return this.openid.claims;
    }
    return [];
  }

  getRejectedOIDCClaims() {
    this.rejected ||= {};
    return this.getOIDCClaims.call(this.rejected);
  }

  getOIDCClaimsFiltered(filter) {
    if (Array.isArray(filter)) {
      filter = new Set(filter);
    } else if (!(filter instanceof Set)) {
      throw new TypeError('"filter" must be an instance of Set');
    }
    const granted = this.getOIDCClaims();
    return granted.filter(Set.prototype.has.bind(filter));
  }

  addOIDCClaims(claims) {
    if (claims instanceof Set) {
      claims = [...claims];
    } else if (!Array.isArray(claims)) {
      throw new TypeError('"claims" must be an array');
    }
    if (claims.some((claim) => typeof claim !== 'string')) {
      throw new TypeError('"claims" must be an array of strings');
    }
    this.openid ||= {};
    if (this.openid.claims) {
      this.openid.claims = [...new Set([...this.openid.claims, ...claims])];
    } else {
      this.openid.claims = claims;
    }
  }

  rejectOIDCClaims(...args) {
    this.rejected ||= {};
    this.addOIDCClaims.call(this.rejected, ...args);
  }

  getOIDCClaimsEncountered() {
    const granted = this.getOIDCClaims();
    const rejected = this.getRejectedOIDCClaims();
    return granted.concat(rejected);
  }
};
