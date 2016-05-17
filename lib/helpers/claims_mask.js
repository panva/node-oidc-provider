'use strict';

const _ = require('lodash');
const assert = require('assert');
const crypto = require('crypto');

module.exports = function getClaimsMask(config) {
  return class ClaimsMask {

    static sub(accountId, sector) {
      if (!accountId) {
        return undefined;
      }

      if (sector) {
        const shasum = crypto.createHash('sha256');

        shasum.update(sector);
        shasum.update(accountId);
        shasum.update(config.pairwiseSalt);

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

    set scope(scopeParam) {
      this._scope = scopeParam;
      const scope = scopeParam || '';
      assert(_.isEmpty(this.mask),
        'scope cannot be assigned after mask has been set');
      scope.split(' ').forEach((a) => {
        this.mask = config.claims[a];
      });
    }

    get mask() {
      return this._mask || {};
    }

    set mask(mask) {
      const maskObject = mask || {};
      this._mask = _.merge(this.mask, maskObject);
    }

    result() {
      const include = _.chain(this.mask)
        .pickBy((value) => {
          if (value === null) {
            return true;
          }

          if (!_.isPlainObject(value)) {
            return false;
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

          return false;
        })
        .keys()
        .intersection(config.claimsSupported)
        .value();

      const claims = _.chain(this.available).pick(include).value();

      if (this.sector && claims.sub) {
        claims.sub = this.constructor.sub(claims.sub, this.sector);
      }

      return claims;
    }
  };
};
