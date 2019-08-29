const { strict: assert } = require('assert');

const { JWE, JWKS, JWS } = require('@panva/jose');

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
  // TODO: this does not need to be async anymore
  static async sign(payload, key, alg, options = {}) {
    const header = { ...options.fields, alg, typ: options.typ !== undefined ? options.typ : typ };
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

    header.kid = key.kty !== 'oct' ? key.kid : undefined;
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
    ignoreAzp, ignoreIssued, ignoreNotBefore, issuer, jti,
  } = {}) {
    const timestamp = epochTime();

    assert.equal(typeof payload, 'object', 'payload is not of JWT type (JSON serialized object)');

    if (typeof payload.nbf !== 'undefined' && !ignoreNotBefore) {
      assert.equal(typeof payload.nbf, 'number', 'invalid nbf value');
      assert(payload.nbf <= timestamp + clockTolerance, 'jwt not active yet');
    }

    if (typeof payload.iat !== 'undefined' && !ignoreIssued) {
      assert.equal(typeof payload.iat, 'number', 'invalid iat value');
      assert(payload.iat <= timestamp + clockTolerance, 'jwt issued in the future');
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

    if (jti) {
      assert.equal(payload.jti, jti, 'jwt jti invalid');
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
    const { payload, header } = JWT.decode(jwt);
    JWT.assertHeader(header, options);
    try {
      JWS.verify(jwt, keyOrStore, { complete: true });
    } catch (err) {
      if (isKeyStore(keyOrStore)) {
        await keyOrStore.refresh();
        JWS.verify(jwt, keyOrStore, { complete: true });
      } else {
        throw err;
      }
    }

    this.assertPayload(payload, options);
    return { payload, header };
  }

  // TODO: this does not need to be async anymore
  static async encrypt(cleartext, key, { enc, alg, cty = typ } = {}) {
    const header = {
      alg, enc, cty, kid: key.kty !== 'oct' ? key.kid : undefined,
    };

    return JWE.encrypt(cleartext, key, header);
  }

  // TODO: this does not need to be async anymore
  static async decrypt(jwt, keystore) {
    return JWE.decrypt(jwt, keystore);
  }
}

module.exports = JWT;
