const signingAlgValues = [
  'HS256', 'HS384', 'HS512',
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES256K', 'ES384', 'ES512',
  'EdDSA',
];

const encryptionAlgValues = [
  // asymmetric
  'RSA-OAEP',
  'RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512',
  'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
  // symmetric
  'A128GCMKW', 'A192GCMKW', 'A256GCMKW', 'A128KW', 'A192KW', 'A256KW',
  // direct
  'dir',
];

const encryptionEncValues = [
  'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
];

export const clientAuthSigningAlgValues = [...signingAlgValues];
export const idTokenSigningAlgValues = [...signingAlgValues];
export const requestObjectSigningAlgValues = [...signingAlgValues];
export const userinfoSigningAlgValues = [...signingAlgValues];
export const introspectionSigningAlgValues = [...signingAlgValues];
export const authorizationSigningAlgValues = [...signingAlgValues];
export const idTokenEncryptionAlgValues = [...encryptionAlgValues];
export const requestObjectEncryptionAlgValues = [...encryptionAlgValues];
export const userinfoEncryptionAlgValues = [...encryptionAlgValues];
export const introspectionEncryptionAlgValues = [...encryptionAlgValues];
export const authorizationEncryptionAlgValues = [...encryptionAlgValues];
export const idTokenEncryptionEncValues = [...encryptionEncValues];
export const requestObjectEncryptionEncValues = [...encryptionEncValues];
export const userinfoEncryptionEncValues = [...encryptionEncValues];
export const introspectionEncryptionEncValues = [...encryptionEncValues];
export const authorizationEncryptionEncValues = [...encryptionEncValues];
export const dPoPSigningAlgValues = [...signingAlgValues].filter((alg) => !alg.startsWith('HS'));
