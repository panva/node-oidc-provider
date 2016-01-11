'use strict';

let jose = require('node-jose');
let base64url = require('base64url');
let assert = require('assert');

function getSignOptions(payload, options) {
  options = options || {};

  let timestamp = Math.floor(Date.now() / 1000);

  if (!options.noTimestamp) {
    payload.iat = payload.iat || timestamp;
  }
  if (options.expiresIn) {
    payload.exp = timestamp + options.expiresIn;
  }
  if (options.audience) {
    payload.aud = options.audience;
  }
  if (options.issuer) {
    payload.iss = options.issuer;
  }
  if (options.subject) {
    payload.sub = options.subject;
  }

  return options;
}

function verifyAudience(payload, audiences) {
  var target = Array.isArray(payload.aud) ? payload.aud : [payload.aud];

  var match = target.some(function (aud) {
    return audiences.indexOf(aud) !== -1;
  });
  assert(match, 'jwt audience invalid. expected: ' + audiences.join(' or '));
}

class JWT {

  static sign(payload, key, alg, options) {
    options = getSignOptions(payload, options);
    let j = JSON.stringify;

    let fields = {
      alg: alg,
      typ: 'JWT',
    };

    Object.assign(fields, options.headers);

    if (alg === 'none') {
      let unsigned = [
        base64url(j(fields)), base64url(j(payload)), ''
      ].join('.');

      return Promise.resolve(unsigned);
    }

    return jose.JWS.createSign({
      fields: fields,
      format: 'compact',
    }, {
      key: key,
      reference: !alg.startsWith('HS'),
    }).update(j(payload)).final();
  }

  static decode(jwt) {
    jwt = jwt.split('.');
    return {
      header: JSON.parse(base64url.decode(jwt[0])),
      payload: JSON.parse(base64url.decode(jwt[1])),
    };
  }

  static verify(jwt, key, options) {
    options = options || {};
    let timestamp = Math.floor(Date.now() / 1000);

    return jose.JWS.createVerify(key).verify(jwt).then((jws) => {
      let payload = jws.payload = JSON.parse(jws.payload);
      assert(typeof payload === 'object',
        'payload is not of JWT type (JSON serialized object)');

      if (typeof payload.nbf !== 'undefined' && !options.ignoreNotBefore) {
        assert(typeof payload.nbf === 'number', 'invalid nbf value');
        assert(payload.nbf <= timestamp, 'jwt not active yet');
      }

      if (typeof payload.iat !== 'undefined' && !options.ignoreIssued) {
        assert(typeof payload.iat === 'number', 'invalid iat value');
        assert(payload.iat <= timestamp, 'jwt issued in the future');
      }

      if (typeof payload.exp !== 'undefined' && !options.ignoreExpiration) {
        assert(typeof payload.exp === 'number', 'invalid exp value');
        assert(timestamp < payload.exp, 'jwt expired');
      }

      if (options.audience) {
        verifyAudience(payload, Array.isArray(options.audience) ?
          options.audience : [options.audience]);
      }

      if (options.issuer) {
        assert(payload.iss === options.issuer,
          'jwt issuer invalid. expected: ' + options.issuer);
      }

      if (options.maxAge) {
        assert(typeof payload.iat === 'number', 'iat is missing or invalid');
        assert(timestamp - payload.iat <= options.maxAge, 'maxAge exceeded');
      }

      return jws;
    });
  }

  static encrypt(cleartext, key, enc, alg) {
    return jose.JWE.createEncrypt({
      fields: {
        alg: alg,
        cty: 'JWT',
        enc: enc,
      },
      format: 'compact',
    }, key).update(cleartext).final();
  }

  static decrypt(jwt, keystore) {
    return jose.JWE.createDecrypt(keystore).decrypt(jwt);
  }

}

module.exports = JWT;
