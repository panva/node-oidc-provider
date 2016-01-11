'use strict';

let _ = require('lodash');
let assert = require('assert');
let crypto = require('crypto');

module.exports = function (config) {
  return class ClaimsMask {

    static sub(accountId, sector) {
      if (!accountId) {
        return undefined;
      }

      if (sector) {

        let shasum = crypto.createHash('sha256');

        shasum.update(sector);
        shasum.update(accountId);
        shasum.update('salt');

        return shasum.digest('hex');
      }

      return accountId;
    }

    constructor(available, sector) {
      this.available = available;
      this.sector = sector;
    }

    get scope() {
      return this._scope;
    }

    set scope(scope) {
      this._scope = scope;
      scope = scope || '';
      assert(_.isEmpty(this.mask),
        'scope cannot be assigned after mask has been set');
      scope.split(' ').forEach((scope) => {
        this.mask = config.claims[scope];
      });
    }

    get mask() {
      return this._mask || {};
    }

    set mask(mask) {
      mask = mask || {};
      this._mask = _.merge(this.mask, mask);
    }

    result() {
      let include = _.chain(this.mask).pickBy((value) => {
        if (value === null) {
          return true;
        }

        if (value.value !== undefined) {
          return true;
        }

        if (value.values !== undefined) {
          return true;
        }

        if (value.essential !== undefined) {
          return true;
        }

      }).keys().intersection(config.claimsSupported).value();

      let claims = _.chain(this.available).pick(include).value();

      if (this.sector && claims.sub) {
        claims.sub = this.constructor.sub(claims.sub, this.sector);
      }

      return claims;
    }
  };
};
