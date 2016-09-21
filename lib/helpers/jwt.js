'use strict';

const jose = require('node-jose');
const base64url = require('base64url');
const uuid = require('uuid');
const assert = require('assert');

const format = 'compact';

function getSignOptions(payload, options) {
  const opts = options || /* istanbul ignore next */ {};

  const timestamp = Math.floor(Date.now() / 1000);

  if (!opts.noTimestamp) payload.iat = payload.iat || timestamp;
  if (opts.expiresIn) payload.exp = timestamp + opts.expiresIn;
  if (opts.audience) payload.aud = opts.audience;
  if (opts.issuer) payload.iss = opts.issuer;
  if (opts.subject) payload.sub = opts.subject;

  return opts;
}

function verifyAudience(payload, audiences) {
  const target = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  const match = target.some(aud => audiences.indexOf(aud) !== -1);
  assert(match, `jwt audience invalid. expected one of [${audiences.join(', ')}]`);
}

function createVerify(keyOrStore, jwt) {
  if (keyOrStore instanceof Promise) {
    return keyOrStore.then(store => jose.JWS.createVerify(store).verify(jwt));
  }

  try {
    return jose.JWS.createVerify(keyOrStore).verify(jwt);
  } catch (err) {
    return Promise.reject(err);
  }
}

class JWT {

  static sign(payload, key, alg, options) {
    const opts = getSignOptions(payload, options);
    const j = JSON.stringify;

    const fields = { alg, typ: 'JWT' };

    Object.assign(fields, opts.headers);

    if (alg === 'none') {
      const unsigned = [base64url(j(fields)), base64url(j(payload)), ''].join('.');
      return Promise.resolve(unsigned);
    }

    return jose.JWS.createSign(
      { fields, format },
      { key, reference: opts.forceRef || key.kty !== 'oct' }
    ).update(j(payload)).final();
  }

  static decode(jwt) {
    const parts = jwt.toString().split('.');
    return {
      header: JSON.parse(base64url.decode(parts[0])),
      payload: JSON.parse(base64url.decode(parts[1])),
    };
  }

  static assertPayload(payload, options) {
    const timestamp = Math.ceil(Date.now() / 1000);
    const opts = options || /* istanbul ignore next */ {};

    assert(typeof payload === 'object', 'payload is not of JWT type (JSON serialized object)');

    if (typeof payload.nbf !== 'undefined' && !opts.ignoreNotBefore) {
      assert(typeof payload.nbf === 'number', 'invalid nbf value');
      assert(payload.nbf <= timestamp, 'jwt not active yet');
    }

    if (typeof payload.iat !== 'undefined' && !opts.ignoreIssued) {
      assert(typeof payload.iat === 'number', 'invalid iat value');
      assert(payload.iat <= timestamp, 'jwt issued in the future');
    }

    if (typeof payload.exp !== 'undefined' && !opts.ignoreExpiration) {
      assert(typeof payload.exp === 'number', 'invalid exp value');
      assert(timestamp < payload.exp, 'jwt expired');
    }

    if (opts.audience) {
      verifyAudience(payload, Array.isArray(opts.audience) ? opts.audience : [opts.audience]);
    }

    if (opts.issuer) {
      assert(payload.iss === opts.issuer, `jwt issuer invalid. expected: ${opts.issuer}`);
    }
  }

  static verify(jwt, keyOrStore, options) {
    const opts = options || /* istanbul ignore next */ {};
    let verification;

    if (opts.noIntegrity) {
      try {
        verification = Promise.resolve({ payload: base64url.decode(jwt.split('.')[1]) });
      } catch (err) {
        /* istanbul ignore next */
        return Promise.reject(err);
      }
    } else {
      verification = createVerify(keyOrStore, jwt).catch((err) => {
        if (jose.JWK.isKeyStore(keyOrStore) && keyOrStore.stale()) {
          return createVerify(keyOrStore.refresh(), jwt);
        }
        throw err;
      });
    }

    return verification.then((jws) => {
      const payload = jws.payload = JSON.parse(jws.payload);
      this.assertPayload(payload, opts);
      return jws;
    });
  }

  static encrypt(cleartext, key, enc, alg) {
    const fields = { alg, enc, cty: 'JWT' };

    if (alg.startsWith('PBES2')) {
      fields.p2s = base64url(uuid());
      fields.p2c = 4096;
    }

    return jose.JWE.createEncrypt({ format, fields }, { key, reference: key.kty !== 'oct' })
      .update(cleartext).final();
  }

  static decrypt(jwt, keystore) {
    return jose.JWE.createDecrypt(keystore).decrypt(jwt);
  }

}

module.exports = JWT;
