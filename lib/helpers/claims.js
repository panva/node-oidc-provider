'use strict';

const _ = require('lodash');
const assert = require('assert');
const crypto = require('crypto');

module.exports = function getClaims(config) {
  return class Claims {

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
      this.filter = {};
    }

    scope(value) {
      const scope = value || '';
      assert(_.isEmpty(this.filter), 'scope cannot be assigned after mask has been set');
      scope.split(' ').forEach(a => this.mask(config.claims[a]));
      return this;
    }

    mask(value) {
      _.merge(this.filter, value);
    }

    result() {
      const available = this.available;
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
        .intersection(config.claimsSupported)
        .value();

      /* eslint-disable no-underscore-dangle */
      const claims = _.pick(available, include);

      if (available._claim_names && available._claim_sources) {
        claims._claim_names = _.pick(available._claim_names, include);
        claims._claim_sources = _.pick(available._claim_sources, _.values(claims._claim_names));

        if (_.isEmpty(claims._claim_names)) {
          delete claims._claim_names;
          delete claims._claim_sources;
        }
      }
      /* eslint-enable */

      if (this.sector && claims.sub) {
        claims.sub = this.constructor.sub(claims.sub, this.sector);
      }

      return claims;
    }
  };
};
