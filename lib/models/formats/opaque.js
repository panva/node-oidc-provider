import als from '../../helpers/als.js';
import { extraTokenClaims } from '../../helpers/configuration_result.js';
import epochTime from '../../helpers/epoch_time.js';
import { assertPayload } from '../../helpers/jwt.js';
import nanoid from '../../helpers/nanoid.js';
import instance from '../../helpers/weak_cache.js';
import pickPayload from '../payload.js';

const withExtra = new Set(['AccessToken', 'ClientCredentials']);
const bitsPerSymbol = Math.log2(64);
const tokenLength = (i) => Math.ceil(i / bitsPerSymbol);

export default (provider) => ({
  generateTokenId() {
    let length;
    if (this.kind !== 'PushedAuthorizationRequest') {
      const { bitsOfOpaqueRandomness } = instance(provider).configuration.formats;
      if (typeof bitsOfOpaqueRandomness === 'function') {
        length = tokenLength(bitsOfOpaqueRandomness(als.getStore(), this));
      } else {
        length = tokenLength(bitsOfOpaqueRandomness);
      }
    }
    return nanoid(length);
  },
  async getValueAndPayload() {
    const { configuration } = instance(provider);
    const now = epochTime();
    const exp = this.exp || now + this.expiration;
    const payload = {
      iat: this.iat || epochTime(),
      ...(exp ? { exp } : undefined),
    };
    const modelPayload = pickPayload(this.constructor, this);
    for (const [key, value] of Object.entries(modelPayload)) {
      if (typeof value !== 'undefined') {
        Object.defineProperty(payload, key, {
          configurable: true,
          enumerable: true,
          value,
          writable: true,
        });
      }
    }

    if (withExtra.has(this.kind)) {
      payload.extra = this.extra = extraTokenClaims(
        await configuration.extraTokenClaims(als.getStore(), this),
      );
    }

    return { value: this.jti, payload };
  },
  async verify(stored, { ignoreExpiration } = {}) {
    // checks that legacy tokens aren't accepted as opaque when their jti is passed
    if (('jwt' in stored) || ('jwt-ietf' in stored) || ('paseto' in stored)) throw new TypeError();
    if (('format' in stored) && stored.format !== 'opaque') throw new TypeError();

    const { configuration } = instance(provider);
    assertPayload(stored, {
      ignoreExpiration,
      clockTolerance: configuration.clockTolerance,
    });

    return stored;
  },
});
