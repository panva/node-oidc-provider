const isUndefined = require('lodash/isUndefined');
const pickBy = require('lodash/pickBy');

const { assertPayload } = require('../../helpers/jwt');
const epochTime = require('../../helpers/epoch_time');
const instance = require('../../helpers/weak_cache');
const nanoid = require('../../helpers/nanoid');
const ctxRef = require('../ctx_ref');

const withExtra = new Set(['AccessToken', 'ClientCredentials']);

module.exports = (provider) => ({
  // Default nanoid has a (26+26+10+2 = 64) symbol alphabet (6 bits). So with 6 bits per symbol, and
  // 43 symbols => (6*27 = 258) total bits.
  generateTokenId() {
    return nanoid(43);
  },
  async getValueAndPayload() {
    const now = epochTime();
    const exp = this.exp || now + this.expiration;
    const value = this.jti;
    const payload = {
      iat: this.iat || epochTime(),
      ...(exp ? { exp } : undefined),
      ...pickBy(
        this,
        (val, key) => this.constructor.IN_PAYLOAD.includes(key) && !isUndefined(val),
      ),
    };

    if (withExtra.has(this.kind)) {
      payload.extra = await instance(provider).configuration('extraAccessTokenClaims')(ctxRef.get(this), this);
    }

    return [value, payload];
  },
  getTokenId(token) {
    return token;
  },
  async verify(token, stored, { ignoreExpiration, foundByReference }) {
    assertPayload(stored, {
      ignoreExpiration,
      clockTolerance: instance(provider).configuration('clockTolerance'),
      ...(foundByReference ? undefined : { jti: token }),
    });

    return stored;
  },
});
