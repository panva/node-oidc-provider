import { compactDecrypt, decodeProtectedHeader, importJWK } from 'jose';

import { json, jwt } from '../shared/selective_body.js';
import isJsonObject from './_/is_json_object.js';
import { InvalidCredentialRequest, InvalidEncryptionParameters } from './errors.js';
import * as JWT from './jwt.js';
import instance from './weak_cache.js';

export function getCredentialRequestEncryptionKeys(provider) {
  const { configuration, jwks, keystore } = instance(provider);
  const keys = jwks.keys.filter((key) => (
    configuration.enabledJWA.credentialEncryptionAlgValues.includes(key.alg)
    && keystore.selectForDecrypt({ alg: key.alg, kid: key.kid }).length
  ));

  if (!keys.length) {
    throw new TypeError('features.openid4vci.credentialRequestEncryption requires a usable provider encryption key with an enabled explicit alg');
  }
  return { keys };
}

export async function parseCredentialRequest(ctx, next) {
  const { configuration, keystore } = instance(ctx.oidc.provider);
  const settings = configuration.features.openid4vci.credentialRequestEncryption;

  if (!ctx.is('application/jwt')) {
    if (settings?.required) {
      throw new InvalidCredentialRequest('credential request encryption is required');
    }
    return json(ctx, next);
  }

  if (!settings) {
    throw new InvalidCredentialRequest('credential request encryption is not supported');
  }

  try {
    await jwt(ctx, async () => {
      const { body } = ctx.oidc;
      const header = decodeProtectedHeader(body);
      const advertised = getCredentialRequestEncryptionKeys(ctx.oidc.provider).keys.find((key) => (
        key.kid === header.kid && key.alg === header.alg
      ));

      if (!advertised) {
        throw new Error('unsupported credential request encryption parameters');
      }

      const [key] = keystore.selectForDecrypt({ alg: header.alg, kid: header.kid, epk: header.epk });
      const { plaintext } = await compactDecrypt(body, keystore.getKeyObject(key), {
        keyManagementAlgorithms: [advertised.alg],
        contentEncryptionAlgorithms: configuration.enabledJWA.credentialEncryptionEncValues,
        maxDecompressedLength: 0,
      });
      ctx.oidc.body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext));
    });
  } catch (cause) {
    throw new InvalidCredentialRequest('could not decrypt credential request', { cause });
  }

  return next();
}

export async function encryptCredentialResponse(ctx, next) {
  const { configuration } = instance(ctx.oidc.provider);
  const { openid4vci } = configuration.features;
  const settings = openid4vci.credentialResponseEncryption;
  const parameters = ctx.oidc.body.credential_response_encryption;

  if (parameters === undefined) {
    if (settings?.required) {
      throw new InvalidEncryptionParameters('credential response encryption parameters are required');
    }
    return next();
  }

  if (!settings) {
    throw new InvalidEncryptionParameters('credential response encryption is not supported');
  }

  // OpenID4VCI 1.0, Section 8.2: encrypt the request to prevent key substitution.
  if (!ctx.is('application/jwt')) {
    throw new InvalidEncryptionParameters('credential request must be encrypted when requesting credential response encryption');
  }

  let key;
  let options;
  try {
    if (!isJsonObject(parameters) || !isJsonObject(parameters.jwk)) {
      throw new Error('credential_response_encryption must contain a public jwk');
    }

    const { jwk, enc, zip } = parameters;
    if (!configuration.enabledJWA.credentialEncryptionAlgValues.includes(jwk.alg)
        || (enc !== undefined && !configuration.enabledJWA.credentialEncryptionEncValues.includes(enc))
        || zip !== undefined) {
      throw new Error('unsupported credential response encryption parameters');
    }

    if ((await importJWK(jwk)).type !== 'public') {
      throw new TypeError('credential response encryption requires a public key');
    }
    key = jwk;
    options = { alg: jwk.alg, enc, fields: { kid: jwk.kid } };

    // Validate usability before application issuance, including low-order ECDH points
    // and RSA key sizes that may pass public-key import but fail encryption.
    await JWT.encrypt('', key, options);
  } catch (cause) {
    throw new InvalidEncryptionParameters('invalid credential response encryption parameters', { cause });
  }

  await next();

  ctx.body = await JWT.encrypt(JSON.stringify(ctx.body), key, options);
  ctx.type = 'application/jwt';
}
