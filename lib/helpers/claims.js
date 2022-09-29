import instance from './weak_cache.js';
import pick from './_/pick.js';
import merge from './_/merge.js';
import isPlainObject from './_/is_plain_object.js';

export default function getClaims(provider) {
  const {
    claims: claimConfig, claimsSupported, pairwiseIdentifier,
  } = instance(provider).configuration();

  return class Claims {
    constructor(available, { ctx, client = ctx ? ctx.oidc.client : undefined }) {
      if (!isPlainObject(available)) {
        throw new TypeError('expected claims to be an object, are you sure claims() method resolves with or returns one?');
      }
      if (!(client instanceof provider.Client)) {
        throw new TypeError('second argument must be a Client instance');
      }
      this.available = available;
      this.client = client;
      this.ctx = ctx;
      this.filter = {};
    }

    scope(value = '') {
      if (Object.keys(this.filter).length) {
        throw new Error('scope cannot be assigned after mask has been set');
      }
      value.split(' ').forEach((scope) => {
        this.mask(claimConfig[scope]);
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

      const claims = pick(available, ...include);

      if (available._claim_names && available._claim_sources) {
        claims._claim_names = pick(available._claim_names, ...include);
        claims._claim_sources = pick(
          available._claim_sources,
          ...Object.values(claims._claim_names),
        );

        if (!Object.keys(claims._claim_names).length) {
          delete claims._claim_names;
          delete claims._claim_sources;
        }
      }

      if (this.client.subjectType === 'pairwise' && claims.sub) {
        claims.sub = await pairwiseIdentifier(this.ctx, claims.sub, this.client);
      }

      return claims;
    }
  };
}
