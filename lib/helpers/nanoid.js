import { randomFillSync } from 'node:crypto';

export const urlAlphabet = 'useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict';

const POOL_SIZE = 4096;

/*
 * Transcribed from nanoid's customAlphabet so that identifier values, their
 * alphabet and their distribution are unchanged.
 *
 * `mask` is the smallest 2^k - 1 that covers the alphabet. When it equals
 * alphabet.length - 1 the alphabet fills the mask exactly and every masked byte
 * is usable; otherwise masked values landing past the end of the alphabet are
 * rejected rather than folded back in with a modulo, which is what keeps the
 * distribution uniform.
 *
 * Character codes are pooled, as nanoid pools them, so that issuing an
 * identifier does not cost a randomFillSync each time - without pooling this is
 * ~18x slower, and every access token, refresh token, session and grant id goes
 * through here. Unlike nanoid the id is copied out of the pool rather than
 * sliced out of a pooled string, so a live id does not keep the pool it came
 * from - and with it other identifiers' bytes - reachable.
 *
 * test/helpers/nanoid_parity.test.js holds this to nanoid itself.
 */
export function customAlphabet(alphabet, defaultSize) {
  const { length } = alphabet;
  for (let i = 0; i < length; i += 1) {
    if (alphabet.charCodeAt(i) > 255) throw new TypeError('alphabet must be latin1');
  }
  const charCodes = Uint8Array.from(alphabet, (char) => char.charCodeAt(0));

  const mask = (2 << (31 - Math.clz32((length - 1) | 1))) - 1;
  const exact = mask === length - 1;

  const pool = Buffer.allocUnsafe(POOL_SIZE);
  let offset = POOL_SIZE;

  function refill() {
    if (exact) {
      randomFillSync(pool);
      for (let i = 0; i < POOL_SIZE; i += 1) pool[i] = charCodes[pool[i] & mask];
    } else {
      const scratch = Buffer.allocUnsafe(Math.ceil((1.6 * (mask + 1) * POOL_SIZE) / length));
      let accepted = 0;
      while (accepted < POOL_SIZE) {
        randomFillSync(scratch);
        for (let i = 0; i < scratch.length && accepted < POOL_SIZE; i += 1) {
          const index = scratch[i] & mask;
          if (index < length) {
            pool[accepted] = charCodes[index];
            accepted += 1;
          }
        }
      }
    }
    offset = 0;
  }

  return (size = defaultSize) => {
    // nanoid's coercion and guard: formats.bitsOfOpaqueRandomness is
    // configurable and feeds this, and a negative size has to fail loudly
    // rather than hand back an empty token value
    size |= 0; // eslint-disable-line no-param-reassign
    if (size < 0) throw new RangeError('Wrong ID size');
    if (size === 0) return '';

    let id = '';
    let remaining = size;
    while (remaining > 0) {
      if (offset === POOL_SIZE) refill();
      const take = Math.min(remaining, POOL_SIZE - offset);
      // toString copies; a substring would keep the whole pool alive
      id += pool.toString('latin1', offset, offset + take);
      offset += take;
      remaining -= take;
    }
    return id;
  };
}

export default customAlphabet(urlAlphabet, 43);
