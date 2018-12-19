const assert = require('assert');

const base64url = require('base64url');
const {
  JWK: { createKeyStore },
  JWS: { createSign, createVerify },
  JWE: { createEncrypt, createDecrypt },
} = require('node-jose');

const JWKStore = createKeyStore().constructor;

function isKeyStore(obj) {
  return obj instanceof JWKStore;
}

const epochTime = require('./epoch_time');

const { stringify, parse } = JSON;
const format = 'compact';
const typ = 'JWT';

function verifyAudience({ aud, azp }, expected, checkAzp) {
  if (Array.isArray(aud)) {
    const match = aud.some(actual => actual === expected);
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
    const fields = { alg, typ };
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
      return [base64url(stringify(fields)), base64url(stringify(payload)), ''].join('.');
    }

    return createSign({ fields, format }, { key, reference: key.kty !== 'oct' })
      .update(stringify(payload), 'utf8')
      .final();
  }

  static decode(jwt) {
    const parts = String(jwt).split('.');
    return {
      header: parse(base64url.decode(parts[0])),
      payload: parse(base64url.decode(parts[1])),
    };
  }

  static header(jwt) {
    return parse(base64url.decode(jwt.toString().split('.')[0]));
  }

  static assertPayload(payload, {
    clockTolerance = 0, audience, ignoreExpiration,
    ignoreAzp, ignoreIssued, ignoreNotBefore, issuer, jti,
  } = {}) {
    const timestamp = epochTime();

    assert.deepEqual(typeof payload, 'object', 'payload is not of JWT type (JSON serialized object)');

    if (typeof payload.nbf !== 'undefined' && !ignoreNotBefore) {
      assert.deepEqual(typeof payload.nbf, 'number', 'invalid nbf value');
      assert(payload.nbf <= timestamp + clockTolerance, 'jwt not active yet');
    }

    if (typeof payload.iat !== 'undefined' && !ignoreIssued) {
      assert.deepEqual(typeof payload.iat, 'number', 'invalid iat value');
      assert(payload.iat <= timestamp + clockTolerance, 'jwt issued in the future');
    }

    if (typeof payload.exp !== 'undefined' && !ignoreExpiration) {
      assert.deepEqual(typeof payload.exp, 'number', 'invalid exp value');
      assert(timestamp - clockTolerance < payload.exp, 'jwt expired');
    }

    if (jti) {
      assert.deepEqual(payload.jti, jti, 'jwt jti invalid');
    }

    if (audience) {
      verifyAudience(
        payload,
        audience,
        !ignoreAzp,
      );
    }

    if (issuer) {
      assert.deepEqual(payload.iss, issuer, 'jwt issuer invalid');
    }
  }

  static async verify(jwt, keyOrStore, options = {}) {
    let verified;
    try {
      verified = await createVerify(keyOrStore).verify(jwt);
    } catch (err) {
      if (isKeyStore(keyOrStore)) {
        await keyOrStore.refresh();
        verified = await createVerify(keyOrStore).verify(jwt);
      } else {
        throw err;
      }
    }

    verified.payload = parse(verified.payload);
    this.assertPayload(verified.payload, options);
    return verified;
  }

  static async encrypt(cleartext, key, enc, alg, cty = typ) {
    const fields = { alg, enc, cty };

    return createEncrypt({ format, fields }, { key, reference: key.kty !== 'oct' })
      .update(cleartext)
      .final();
  }

  static async decrypt(jwt, keystore) {
    return createDecrypt(keystore).decrypt(jwt);
  }
}

module.exports = JWT;
