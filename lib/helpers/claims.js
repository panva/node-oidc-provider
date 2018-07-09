const assert = require('assert');
const crypto = require('crypto');

const _ = require('lodash');

module.exports = function getClaims({ pairwiseSalt, claims: claimConfig, claimsSupported }) {
  return class Claims {
    static sub(accountId, sector) {
      if (!accountId) return undefined;

      if (sector) {
        return crypto.createHash('sha256')
          .update(sector)
          .update(accountId)
          .update(pairwiseSalt)
          .digest('hex');
      }

      return accountId;
    }

    constructor(available, sector) {
      assert.equal(
        typeof available, 'object',
        'expected claims to be an object, are you sure claims() method resolves with or returns one?',
      );
      this.available = available;
      this.sector = sector;
      this.filter = {};
    }

    scope(value = '') {
      assert(!Object.keys(this.filter).length, 'scope cannot be assigned after mask has been set');
      value.split(' ').forEach(a => this.mask(claimConfig[a]));
      return this;
    }

    mask(value) {
      _.merge(this.filter, value);
    }

    result() {
      const { available } = this;
      const include = Object.entries(this.filter)
        .map(([key, value]) => {
          if (value === null) {
            return key;
          }

          if (!_.isPlainObject(value)) {
            return undefined;
          }

          if (value.value !== undefined) {
            return key;
          }

          if (value.values !== undefined) {
            return key;
          }

          if (value.essential !== undefined) {
            return key;
          }

          return undefined;
        })
        .filter(key => key && claimsSupported.includes(key));

      const claims = _.pick(available, include);

      if (available._claim_names && available._claim_sources) {
        claims._claim_names = _.pick(available._claim_names, include);
        claims._claim_sources = _.pick(
          available._claim_sources,
          Object.values(claims._claim_names),
        );

        if (!Object.keys(claims._claim_names).length) {
          delete claims._claim_names;
          delete claims._claim_sources;
        }
      }

      if (this.sector && claims.sub) {
        claims.sub = this.constructor.sub(claims.sub, this.sector);
      }

      return claims;
    }
  };
};
