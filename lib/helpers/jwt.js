import {
  CompactEncrypt,
  CompactSign,
  compactDecrypt,
  compactVerify,
  decodeProtectedHeader,
  errors,
} from 'jose';

import * as base64url from './base64url.js';
import epochTime from './epoch_time.js';

const { JWEDecryptionFailed, JWKSNoMatchingKey, JWSSignatureVerificationFailed } = errors;

const typ = 'JWT';

function verifyAudience({ aud, azp }, expected, checkAzp) {
  if (Array.isArray(aud)) {
    const match = aud.some((actual) => actual === expected);
    if (!match) throw new Error(`jwt audience missing ${expected}`);
    if (checkAzp) {
      if (!azp) throw new Error('jwt missing azp claim');
      if (azp !== expected) throw new Error('invalid jwt azp');
    }
  } else if (aud !== expected) {
    throw new Error(`jwt audience missing ${expected}`);
  }
}

export async function sign(payload, key, alg, options = {}) {
  const protectedHeader = {
    alg,
    typ: options.typ !== undefined ? options.typ : typ,
    ...options.fields,
  };
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

  return new CompactSign(Buffer.from(JSON.stringify(payload)))
    .setProtectedHeader(protectedHeader)
    .sign(key);
}

export function decode(input) {
  let jwt;

  if (Buffer.isBuffer(input)) {
    jwt = input.toString('utf8');
  } else if (typeof input !== 'string') {
    throw new TypeError('invalid JWT.decode input type');
  } else {
    jwt = input;
  }

  const { 0: protectedHeader, 1: payload, length } = jwt.split('.');

  if (length !== 3) {
    throw new TypeError('invalid JWT.decode input');
  }

  return {
    header: JSON.parse(base64url.decode(protectedHeader)),
    payload: JSON.parse(base64url.decode(payload)),
  };
}

export function header(jwt) {
  return JSON.parse(base64url.decode(jwt.toString().split('.')[0]));
}

export function assertHeader(protectedHeader, { algorithm }) {
  if (algorithm !== undefined) {
    if (protectedHeader.alg !== algorithm) throw new Error('unexpected JWT header alg value');
  }
}

export function assertPayload(payload, {
  clockTolerance = 0, audience, ignoreExpiration,
  ignoreAzp, ignoreIssued, ignoreNotBefore, issuer,
  subject = false,
} = {}) {
  const timestamp = epochTime();

  if (typeof payload !== 'object') throw new Error('payload is not of JWT type (JSON serialized object)');

  if (payload.nbf !== undefined && !ignoreNotBefore) {
    if (typeof payload.nbf !== 'number') throw new Error('invalid nbf value');
    if (payload.nbf > timestamp + clockTolerance) throw new Error('jwt not active yet');
  }

  if (payload.iat !== undefined && !ignoreIssued) {
    if (typeof payload.iat !== 'number') throw new Error('invalid iat value');
    if (payload.exp === undefined && payload.iat > timestamp + clockTolerance) {
      throw new Error('jwt issued in the future');
    }
  }

  if (payload.exp !== undefined && !ignoreExpiration) {
    if (typeof payload.exp !== 'number') throw new Error('invalid exp value');
    if (timestamp - clockTolerance >= payload.exp) throw new Error('jwt expired');
  }

  if (payload.jti !== undefined && typeof payload.jti !== 'string') {
    throw new Error('invalid jti value');
  }

  if (payload.iss !== undefined && typeof payload.iss !== 'string') {
    throw new Error('invalid iss value');
  }

  if (subject && typeof payload.sub !== 'string') {
    throw new Error('invalid sub value');
  }

  if (audience) {
    verifyAudience(
      payload,
      audience,
      !ignoreAzp,
    );
  }

  if (issuer && payload.iss !== issuer) throw new Error('jwt issuer invalid');
}

export async function verify(jwt, keystore, options = {}) {
  let verified;
  try {
    const protectedHeader = decodeProtectedHeader(jwt);

    const keys = keystore.selectForVerify({ alg: protectedHeader.alg, kid: protectedHeader.kid });
    if (keys.length === 0) {
      throw new JWKSNoMatchingKey();
    } else {
      for (const key of keys) {
        try {
          // eslint-disable-next-line no-await-in-loop
          verified = await compactVerify(
            jwt,
            // eslint-disable-next-line no-await-in-loop
            await keystore.getKeyObject(key, protectedHeader.alg),
            { algorithms: options.algorithm ? [options.algorithm] : undefined },
          );
        } catch {}
      }
    }

    if (!verified) {
      throw new JWSSignatureVerificationFailed();
    }
  } catch (err) {
    if (typeof keystore.fresh !== 'function' || keystore.fresh()) {
      throw err;
    }

    await keystore.refresh();
    // eslint-disable-next-line prefer-rest-params
    return verify(...arguments);
  }

  const payload = JSON.parse(Buffer.from(verified.payload));

  assertPayload(payload, options);
  return { payload, header: verified.protectedHeader };
}

export async function encrypt(cleartext, key, {
  enc, alg, fields,
} = {}) {
  const protectedHeader = {
    alg, enc, ...fields,
  };

  return new CompactEncrypt(Buffer.from(cleartext))
    .setProtectedHeader(protectedHeader)
    .encrypt(key);
}

export async function decrypt(jwe, keystore) {
  const protectedHeader = decodeProtectedHeader(jwe);

  const keys = keystore.selectForDecrypt({ alg: protectedHeader.alg === 'dir' ? protectedHeader.enc : protectedHeader.alg, kid: protectedHeader.kid, epk: protectedHeader.epk });
  let decrypted;
  if (keys.length === 0) {
    throw new JWKSNoMatchingKey();
  } else {
    for (const key of keys) {
      try {
        // eslint-disable-next-line no-await-in-loop
        decrypted = await compactDecrypt(jwe, await keystore.getKeyObject(key, protectedHeader.alg === 'dir' ? protectedHeader.enc : protectedHeader.alg));
      } catch {}
    }
  }

  if (!decrypted) {
    throw new JWEDecryptionFailed();
  }

  return Buffer.from(decrypted.plaintext);
}
