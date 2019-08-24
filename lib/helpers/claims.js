const { strict: assert } = require('assert');

const isPlainObject = require('lodash/isPlainObject');
const merge = require('lodash/merge');
const pick = require('lodash/pick');

const instance = require('./weak_cache');

module.exports = function getClaims(provider) {
  const {
    claims: claimConfig, claimsSupported, scopes, dynamicScopes, pairwiseIdentifier,
  } = instance(provider).configuration();

  return class Claims {
    constructor(available, { ctx, client = ctx ? ctx.oidc.client : undefined }) {
      assert.equal(
        typeof available, 'object',
        'expected claims to be an object, are you sure claims() method resolves with or returns one?',
      );
      assert(client instanceof provider.Client, 'second argument must be a Client instance');
      this.available = available;
      this.client = client;
      this.ctx = ctx;
      this.filter = {};
    }

    scope(value = '') {
      assert(!Object.keys(this.filter).length, 'scope cannot be assigned after mask has been set');
      value.split(' ').forEach((scope) => {
        if (!scopes.has(scope)) {
          for (const dynamic of dynamicScopes) { // eslint-disable-line no-restricted-syntax
            if (dynamic.test(scope)) {
              scope = dynamic; // eslint-disable-line no-param-reassign
              break;
            }
          }
        }

        this.mask(claimConfig.get(scope));
      });
      return this;
    }

    mask(value) {
      merge(this.filter, value);
    }

    rejected(value = []) {
      value.forEach((claim) => {
        delete this.filter[claim];
      });
    }

    async result() {
      const { available } = this;
      const include = Object.entries(this.filter)
        .map(([key, value]) => {
          if (value === null || isPlainObject(value)) {
            return key;
          }

          return undefined;
        })
        .filter((key) => key && claimsSupported.has(key));

      const claims = pick(available, include);

      if (available._claim_names && available._claim_sources) {
        claims._claim_names = pick(available._claim_names, include);
        claims._claim_sources = pick(
          available._claim_sources,
          Object.values(claims._claim_names),
        );

        if (!Object.keys(claims._claim_names).length) {
          delete claims._claim_names;
          delete claims._claim_sources;
        }
      }

      if (this.client.sectorIdentifier && claims.sub) {
        claims.sub = await pairwiseIdentifier(this.ctx, claims.sub, this.client);
      }

      return claims;
    }
  };
};
