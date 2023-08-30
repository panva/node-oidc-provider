import pickBy from '../../helpers/_/pick_by.js';
import { assertPayload } from '../../helpers/jwt.js';
import epochTime from '../../helpers/epoch_time.js';
import instance from '../../helpers/weak_cache.js';
import nanoid from '../../helpers/nanoid.js';
import ctxRef from '../ctx_ref.js';

const withExtra = new Set(['AccessToken', 'ClientCredentials']);
const bitsPerSymbol = Math.log2(64);
const tokenLength = (i) => Math.ceil(i / bitsPerSymbol);

export default (provider) => ({
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
      // eslint-disable-next-line no-multi-assign
      payload.extra = this.extra = await instance(provider).configuration('extraTokenClaims')(ctxRef.get(this), this);
    }

    return { value: this.jti, payload };
  },
  async verify(stored, { ignoreExpiration } = {}) {
    // checks that legacy tokens aren't accepted as opaque when their jti is passed
    if (('jwt' in stored) || ('jwt-ietf' in stored) || ('paseto' in stored)) throw new TypeError();
    if (('format' in stored) && stored.format !== 'opaque') throw new TypeError();

    assertPayload(stored, {
      ignoreExpiration,
      clockTolerance: instance(provider).configuration('clockTolerance'),
    });

    return stored;
  },
});
