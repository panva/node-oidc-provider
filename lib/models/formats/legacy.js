const assert = require('assert');
const { randomBytes } = require('crypto');

const { pick } = require('lodash');
const base64url = require('base64url');
const uuid = require('uuid/v4');

const { assertPayload, sign, decode } = require('../../helpers/jwt');
const instance = require('../../helpers/weak_cache');

module.exports = provider => ({
  generateTokenId() {
    return base64url(uuid());
  },
  async getValueAndPayload() {
    const store = pick(this, this.constructor.IN_PAYLOAD);
    delete store.consumed;

    const jwt = await sign(store, undefined, 'none', {
      issuer: provider.issuer,
      ...(this.exp ? undefined : { expiresIn: this.expiration }),
    });

    const [header, payload] = jwt.split('.');
    let signature;

    if (this.signature) {
      ({ signature } = this);
    } else {
      signature = base64url(randomBytes(64));
    }

    return [`${this.jti}${signature}`, {
      header,
      payload,
      signature,
      ...(this.constructor.IN_PAYLOAD.includes('grantId') && this.grantId ? { grantId: this.grantId } : undefined),
    }];
  },
  getTokenId(token) {
    return token.substring(0, 48);
  },
  async verify(token, stored, { ignoreExpiration, foundByUserCode } = {}) {
    if (!foundByUserCode) {
      assert.deepEqual(token.substring(48), stored.signature);
    }
    const { payload } = decode([stored.header, stored.payload, stored.signature].join('.'));
    payload.signature = stored.signature;
    assertPayload(payload, {
      ignoreExpiration,
      issuer: provider.issuer,
      clockTolerance: instance(provider).configuration('clockTolerance'),
      ...(foundByUserCode ? undefined : { jti: this.getTokenId(token) }),
    });
    return payload;
  },
});
