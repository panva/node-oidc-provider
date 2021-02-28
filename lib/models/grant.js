/* eslint-disable no-restricted-syntax */
/* eslint-disable no-unused-expressions */

const apply = require('./mixins/apply');
const hasFormat = require('./mixins/has_format');

const NON_REJECTABLE_CLAIMS = new Set(['sub', 'sid', 'auth_time', 'acr', 'amr', 'iss']);

module.exports = (provider) => class Grant extends apply([
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
    if (this.openid && this.openid.scope) {
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

  getRejectedOIDCScope(...args) {
    this.rejected || (this.rejected = {});
    return this.getOIDCScope.call(this.rejected, ...args);
  }

  getOIDCScopeFiltered(filter) {
    const granted = this.getOIDCScope().split(' ');
    return granted.filter(Set.prototype.has.bind(filter)).join(' ');
  }

  addOIDCScope(scope) {
    this.openid || (this.openid = {});
    if (this.openid.scope) {
      this.openid.scope = [...new Set([...this.openid.scope.split(' '), ...scope.split(' ')])].join(' ');
    } else {
      this.openid.scope = scope;
    }
  }

  rejectOIDCScope(...args) {
    this.rejected || (this.rejected = {});
    this.addOIDCScope.call(this.rejected, ...args);
  }

  getOIDCScopeEncountered() {
    const granted = this.getOIDCScope().split(' ');
    const rejected = this.getRejectedOIDCScope().split(' ');
    return granted.concat(rejected).join(' ');
  }

  getResourceScope(resource) {
    if (this.resources && this.resources[resource]) {
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
    this.rejected || (this.rejected = {});
    return this.getResourceScope.call(this.rejected, ...args);
  }

  getResourceScopeFiltered(resource, filter) {
    const granted = this.getResourceScope(resource).split(' ');
    return granted.filter(Set.prototype.has.bind(filter)).join(' ');
  }

  addResourceScope(resource, scope) {
    this.resources || (this.resources = {});
    if (this.resources[resource]) {
      this.resources[resource] = [...new Set([...this.resources[resource].split(' '), ...scope.split(' ')])].join(' ');
    } else {
      this.resources[resource] = scope;
    }
  }

  rejectResourceScope(...args) {
    this.rejected || (this.rejected = {});
    this.addResourceScope.call(this.rejected, ...args);
  }

  getResourceScopeEncountered(resource) {
    const granted = this.getResourceScope(resource).split(' ');
    const rejected = this.getRejectedResourceScope(resource).split(' ');
    return granted.concat(rejected).join(' ');
  }

  getOIDCClaims() {
    if (this.openid && this.openid.claims) {
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

  getRejectedOIDCClaims(...args) {
    this.rejected || (this.rejected = {});
    return this.getOIDCClaims.call(this.rejected, ...args);
  }

  getOIDCClaimsFiltered(filter) {
    const granted = this.getOIDCClaims();
    return granted.filter(Set.prototype.has.bind(filter));
  }

  addOIDCClaims(claims) {
    this.openid || (this.openid = {});
    if (this.openid.claims) {
      this.openid.claims = [...new Set([...this.openid.claims, ...claims])];
    } else {
      this.openid.claims = claims;
    }
  }

  rejectOIDCClaims(...args) {
    this.rejected || (this.rejected = {});
    this.addOIDCClaims.call(this.rejected, ...args);
  }

  getOIDCClaimsEncountered(resource) {
    const granted = this.getOIDCClaims(resource);
    const rejected = this.getRejectedOIDCClaims(resource);
    return granted.concat(rejected);
  }
};
