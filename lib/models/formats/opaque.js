const { strict: assert } = require('assert');

const pickBy = require('../../helpers/_/pick_by');
const { assertPayload } = require('../../helpers/jwt');
const epochTime = require('../../helpers/epoch_time');
const instance = require('../../helpers/weak_cache');
const nanoid = require('../../helpers/nanoid');
const ctxRef = require('../ctx_ref');

const withExtra = new Set(['AccessToken', 'ClientCredentials']);
const bitsPerSymbol = Math.log2(64);
const tokenLength = (i) => Math.ceil(i / bitsPerSymbol);

module.exports = (provider) => ({
  generateTokenId() {
    let length;
    if (this.kind !== 'PushedAuthorizationRequest') {
      const bitsOfOpaqueRandomness = instance(provider).configuration('formats.bitsOfOpaqueRandomness');
      if (typeof bitsOfOpaqueRandomness === 'function') {
        length = tokenLength(bitsOfOpaqueRandomness(ctxRef.get(this), this));
      } else {
        length = tokenLength(bitsOfOpaqueRandomness);
      }
    }
    return nanoid(length);
  },
  async getValueAndPayload() {
    const now = epochTime();
    const exp = this.exp || now + this.expiration;
    const payload = {
      iat: this.iat || epochTime(),
      ...(exp ? { exp } : undefined),
      ...pickBy(
        this,
        (val, key) => this.constructor.IN_PAYLOAD.includes(key) && typeof val !== 'undefined',
      ),
    };

    if (withExtra.has(this.kind)) {
      payload.extra = await instance(provider).configuration('extraTokenClaims')(ctxRef.get(this), this);
    }

    return { value: this.jti, payload };
  },
  async verify(stored, { ignoreExpiration } = {}) {
    // checks that legacy tokens aren't accepted as opaque when their jti is passed
    assert(!('jwt' in stored) && !('jwt-ietf' in stored) && !('paseto' in stored));
    assert(!('format' in stored) || stored.format === 'opaque');

    assertPayload(stored, {
      ignoreExpiration,
      clockTolerance: instance(provider).configuration('clockTolerance'),
    });

    return stored;
  },
});
