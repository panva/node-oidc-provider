const _ = require('lodash');
const assert = require('assert');
const crypto = require('crypto');

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
      assert(_.isEmpty(this.filter), 'scope cannot be assigned after mask has been set');
      value.split(' ').forEach(a => this.mask(claimConfig[a]));
      return this;
    }

    mask(value) {
      _.merge(this.filter, value);
    }

    result() {
      const { available } = this;
      const include = _.chain(this.filter)
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
        .intersection(claimsSupported)
        .value();

      const claims = _.pick(available, include);

      if (available._claim_names && available._claim_sources) {
        claims._claim_names = _.pick(available._claim_names, include);
        claims._claim_sources = _.pick(available._claim_sources, _.values(claims._claim_names));

        if (_.isEmpty(claims._claim_names)) {
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
