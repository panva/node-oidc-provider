const base64url = require('base64url');
const uuid = require('uuid');
const assert = require('assert');
const epochTime = require('../helpers/epoch_time');
const {
  JWK: { isKeyStore },
  JWS: { createSign, createVerify },
  JWE: { createEncrypt, createDecrypt },
} = require('node-jose');

const { stringify, parse } = JSON;
const format = 'compact';
const typ = 'JWT';

function verifyAudience(payload, audiences) {
  const target = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  const match = target.some(aud => audiences.includes(aud));
  assert(match, `jwt audience invalid. expected one of [${audiences.join(', ')}]`);
}

class JWT {

  static async sign(payload, key, alg, options = {}) {
    const fields = { alg, typ };
    const timestamp = epochTime();

    Object.assign(payload, {
      iat: payload.iat ? payload.iat : timestamp,
      exp: options.expiresIn ? timestamp + options.expiresIn : payload.exp,
      aud: options.audience ? options.audience : payload.aud,
      iss: options.issuer ? options.issuer : payload.iss,
      sub: options.subject ? options.subject : payload.sub,
    });

    if (alg === 'none') {
      return [base64url(stringify(fields)), base64url(stringify(payload)), ''].join('.');
    }

    return createSign({ fields, format }, { key, reference: key.kty !== 'oct' })
      .update(stringify(payload), 'utf8')
      .final();
  }

  static decode(jwt) {
    const parts = jwt.toString().split('.');
    return {
      header: parse(base64url.decode(parts[0])),
      payload: parse(base64url.decode(parts[1])),
    };
  }

  static header(jwt) {
    return parse(base64url.decode(jwt.toString().split('.')[0]));
  }

  static assertPayload(payload, options = {}) {
    const timestamp = Math.ceil(Date.now() / 1000);

    assert.equal(typeof payload, 'object', 'payload is not of JWT type (JSON serialized object)');

    if (typeof payload.nbf !== 'undefined' && !options.ignoreNotBefore) {
      assert.equal(typeof payload.nbf, 'number', 'invalid nbf value');
      assert(payload.nbf <= timestamp, 'jwt not active yet');
    }

    if (typeof payload.iat !== 'undefined' && !options.ignoreIssued) {
      assert.equal(typeof payload.iat, 'number', 'invalid iat value');
      assert(payload.iat <= timestamp, 'jwt issued in the future');
    }

    if (typeof payload.exp !== 'undefined' && !options.ignoreExpiration) {
      assert.equal(typeof payload.exp, 'number', 'invalid exp value');
      assert(timestamp < payload.exp, 'jwt expired');
    }

    if (options.audience) {
      verifyAudience(payload,
        Array.isArray(options.audience) ? options.audience : [options.audience]);
    }

    if (options.issuer) {
      assert.equal(payload.iss, options.issuer, `jwt issuer invalid. expected: ${options.issuer}`);
    }
  }

  static async verify(jwt, keyOrStore, options = {}) {
    let verified;
    try {
      verified = await createVerify(keyOrStore).verify(jwt);
    } catch (err) {
      if (isKeyStore(keyOrStore) && keyOrStore.stale()) {
        await keyOrStore.refresh();
        verified = await createVerify(keyOrStore).verify(jwt);
      }
      throw err;
    }

    verified.payload = parse(verified.payload);
    this.assertPayload(verified.payload, options);
    return verified;
  }

  static encrypt(cleartext, key, enc, alg) {
    const fields = { alg, enc, cty: typ };

    if (alg.startsWith('PBES2')) {
      fields.p2s = base64url(uuid());
      fields.p2c = 4096;
    }

    return createEncrypt({ format, fields }, { key, reference: key.kty !== 'oct' })
      .update(cleartext)
      .final();
  }

  static decrypt(jwt, keystore) {
    return createDecrypt(keystore).decrypt(jwt);
  }

}

module.exports = JWT;
