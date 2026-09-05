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

export function generateTokenId(provider, token) {
  let length;
  if (token.kind !== 'PushedAuthorizationRequest') {
    const { bitsOfOpaqueRandomness } = instance(provider).configuration.formats;
    if (typeof bitsOfOpaqueRandomness === 'function') {
      length = tokenLength(bitsOfOpaqueRandomness(als.getStore(), token));
    } else {
      length = tokenLength(bitsOfOpaqueRandomness);
    }
  }
  return nanoid(length);
}

export async function getValueAndPayload(provider, token) {
  const { configuration } = instance(provider);
  const now = epochTime();
  const exp = token.exp || now + token.expiration;
  const payload = {
    iat: token.iat || epochTime(),
    ...(exp ? { exp } : undefined),
  };
  const modelPayload = pickPayload(token.constructor, token);
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

  if (withExtra.has(token.kind)) {
    payload.extra = token.extra = extraTokenClaims(
      await configuration.extraTokenClaims(als.getStore(), token),
    );
  }

  return { value: token.jti, payload };
}

export async function verify(provider, stored, { ignoreExpiration } = {}) {
  // checks that legacy tokens aren't accepted as opaque when their jti is passed
  if (('jwt' in stored) || ('jwt-ietf' in stored) || ('paseto' in stored)) throw new TypeError();
  if (('format' in stored) && stored.format !== 'opaque') throw new TypeError();

  const { configuration } = instance(provider);
  assertPayload(stored, {
    ignoreExpiration,
    clockTolerance: configuration.clockTolerance,
  });

  return stored;
}
