const { strict: assert } = require('assert');

const { JWE, JWKS, JWS } = require('jose');

function isKeyStore(obj) {
  return obj instanceof JWKS.KeyStore;
}

const base64url = require('./base64url');
const epochTime = require('./epoch_time');

const typ = 'JWT';

function verifyAudience({ aud, azp }, expected, checkAzp) {
  if (Array.isArray(aud)) {
    const match = aud.some((actual) => actual === expected);
    assert(match, `jwt audience missing ${expected}`);
    if (checkAzp) {
      assert(azp, 'jwt missing azp claim');
      assert.strictEqual(azp, expected, 'invalid jwt azp');
    }
  } else {
    assert.strictEqual(aud, expected, `jwt audience missing ${expected}`);
  }
}

class JWT {
  static async sign(payload, key, alg, options = {}) {
    const header = { alg, typ: options.typ !== undefined ? options.typ : typ, ...options.fields };
    const timestamp = epochTime();

    const iat = options.noIat ? undefined : timestamp;

    Object.assign(payload, {
      aud: options.audience !== undefined ? options.audience : payload.aud,
      azp: options.authorizedParty !== undefined ? options.authorizedParty : payload.azp,
      exp: options.expiresIn !== undefined ? timestamp + options.expiresIn : payload.exp,
      iat: payload.iat !== undefined ? payload.iat : iat,
      iss: options.issuer !== undefined ? options.issuer : payload.iss,
      sub: options.subject !== undefined ? options.subject : payload.sub,
    });

    if (alg === 'none') {
      return [base64url.encode(JSON.stringify(header)), base64url.encode(JSON.stringify(payload)), ''].join('.');
    }

    if (!options.fields || (options.fields && !('kid' in options.fields))) {
      header.kid = key.kty !== 'oct' ? key.kid : undefined;
    }
    return JWS.sign(payload, key, header);
  }

  static decode(input) {
    let jwt;

    if (Buffer.isBuffer(input)) {
      jwt = input.toString('utf8');
    } else if (typeof input !== 'string') {
      throw new TypeError('invalid JWT.decode input type');
    } else {
      jwt = input;
    }

    const { 0: header, 1: payload, length } = jwt.split('.');

    if (length !== 3) {
      throw new TypeError('invalid JWT.decode input');
    }

    return {
      header: JSON.parse(base64url.decode(header)),
      payload: JSON.parse(base64url.decode(payload)),
    };
  }

  static header(jwt) {
    return JSON.parse(base64url.decode(jwt.toString().split('.')[0]));
  }

  static assertHeader(header, { algorithm }) {
    if (algorithm !== undefined) {
      assert.equal(header.alg, algorithm, 'unexpected JWT header alg value');
    }
  }

  static assertPayload(payload, {
    clockTolerance = 0, audience, ignoreExpiration,
    ignoreAzp, ignoreIssued, ignoreNotBefore, issuer,
  } = {}) {
    const timestamp = epochTime();

    assert.equal(typeof payload, 'object', 'payload is not of JWT type (JSON serialized object)');

    if (typeof payload.nbf !== 'undefined' && !ignoreNotBefore) {
      assert.equal(typeof payload.nbf, 'number', 'invalid nbf value');
      assert(payload.nbf <= timestamp + clockTolerance, 'jwt not active yet');
    }

    if (typeof payload.iat !== 'undefined' && !ignoreIssued) {
      assert.equal(typeof payload.iat, 'number', 'invalid iat value');
      if (typeof payload.exp === 'undefined') {
        assert(payload.iat <= timestamp + clockTolerance, 'jwt issued in the future');
      }
    }

    if (typeof payload.exp !== 'undefined' && !ignoreExpiration) {
      assert.equal(typeof payload.exp, 'number', 'invalid exp value');
      assert(timestamp - clockTolerance < payload.exp, 'jwt expired');
    }

    if (typeof payload.jti !== 'undefined') {
      assert.equal(typeof payload.jti, 'string', 'invalid jti value');
    }

    if (typeof payload.iss !== 'undefined') {
      assert.equal(typeof payload.iss, 'string', 'invalid iss value');
    }

    if (audience) {
      verifyAudience(
        payload,
        audience,
        !ignoreAzp,
      );
    }

    if (issuer) {
      assert.equal(payload.iss, issuer, 'jwt issuer invalid');
    }
  }

  static async verify(jwt, keyOrStore, options = {}) {
    const opts = {
      complete: true,
      algorithms: options.algorithm ? [options.algorithm] : undefined,
    };

    let payload;
    let header;

    try {
      ({ protected: header, payload } = JWS.verify(jwt, keyOrStore, opts));
    } catch (err) {
      if (!isKeyStore(keyOrStore) || typeof keyOrStore.fresh !== 'function' || keyOrStore.fresh()) {
        throw err;
      }

      await keyOrStore.refresh();
      ({ protected: header, payload } = JWS.verify(jwt, keyOrStore, opts));
    }

    payload = JSON.parse(payload);

    this.assertPayload(payload, options);
    return { payload, header };
  }

  static async encrypt(cleartext, key, {
    enc, alg, fields,
  } = {}) {
    const header = {
      alg, enc, ...fields,
    };

    if (!fields || (fields && !('kid' in fields))) {
      header.kid = key.kty !== 'oct' ? key.kid : undefined;
    }

    return JWE.encrypt(cleartext, key, header);
  }

  static async decrypt(jwt, keystore) {
    return JWE.decrypt(jwt, keystore);
  }
}

module.exports = JWT;
