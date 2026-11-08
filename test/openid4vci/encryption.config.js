import { webcrypto } from 'node:crypto';

import { exportJWK, generateKeyPair } from 'jose';

import getConfig from '../default.config.js';
import keys from '../keys.js';

export const issuerKeypair = await generateKeyPair('ECDH-ES', { extractable: true });
export const unadvertisedKeypair = await generateKeyPair('ECDH-ES', { extractable: true });
export const rsaIssuerKeypair = await generateKeyPair('RSA-OAEP-256', { extractable: true });
export const issuerJwk = {
  ...await exportJWK(issuerKeypair.publicKey),
  alg: 'ECDH-ES',
  kid: 'credential-encryption',
  use: 'enc',
};
const issuerPrivateJwk = await exportJWK(issuerKeypair.privateKey);
const unadvertisedPrivateJwk = await exportJWK(unadvertisedKeypair.privateKey);
const rsaIssuerPrivateJwk = await exportJWK(rsaIssuerKeypair.privateKey);
export const rsaIssuerJwk = {
  ...await exportJWK(rsaIssuerKeypair.publicKey),
  alg: 'RSA-OAEP-256',
  kid: 'rsa-credential-encryption',
  use: 'enc',
};
const { key_ops, ...nativeDecryptionJwk } = await webcrypto.subtle.exportKey('jwk', await webcrypto.subtle.importKey(
  'jwk', rsaIssuerPrivateJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt'],
));
export const nativeDecryptionKid = 'native-decryption-export';

export const credentialResponse = {
  credentials: [
    { credential: 'issued-credential' },
    { credential: { format: 'example', claim: 'value' } },
  ],
  notification_id: 'notification-example',
};

export function encryptionConfig() {
  const config = getConfig();
  config.enabledJWA.credentialEncryptionAlgValues = ['ECDH-ES', 'RSA-OAEP-256'];
  config.enabledJWA.credentialEncryptionEncValues = ['A128GCM'];
  config.jwks = {
    keys: [
      ...keys,
      { ...issuerPrivateJwk, ...issuerJwk },
      { ...rsaIssuerPrivateJwk, ...rsaIssuerJwk },
      { ...nativeDecryptionJwk, kid: nativeDecryptionKid, alg: 'RSA-OAEP-256' },
    ],
  };
  config.features.encryption = { enabled: true };
  config.features.dPoP = { enabled: true };
  config.features.openid4vci = {
    enabled: true,
    ack: 'experimental-01',
    nonceSecret: Buffer.alloc(32),
    credentialRequestEncryption: {
      required: false,
    },
    credentialResponseEncryption: {
      required: false,
    },
    credentialConfigurationsSupported: {
      example: { format: 'example', scope: 'credential_scope' },
      proof_example: {
        format: 'example',
        scope: 'credential_scope',
        cryptographic_binding_methods_supported: ['jwk'],
        proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } },
      },
    },
    async issueCredential() {
      return structuredClone(credentialResponse);
    },
  };
  return config;
}

const config = encryptionConfig();
config.features.openid4vci.credentialRequestEncryption = true;
config.features.openid4vci.credentialResponseEncryption = true;
config.jwks.keys.push({
  ...unadvertisedPrivateJwk,
  alg: 'ECDH-ES+A256KW',
  kid: 'unadvertised-encryption',
  use: 'enc',
});

export default {
  config,
  clients: [{
    client_id: 'wallet',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    redirect_uris: ['https://wallet.example.com/cb'],
    token_endpoint_auth_method: 'none',
  }],
};
