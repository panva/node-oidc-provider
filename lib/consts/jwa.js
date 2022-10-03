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
  'RSA1_5',
  'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
  // symmetric
  'A128GCMKW', 'A192GCMKW', 'A256GCMKW', 'A128KW', 'A192KW', 'A256KW',
  'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
  // direct
  'dir',
];

const encryptionEncValues = [
  'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
];

module.exports = {
  tokenEndpointAuthSigningAlgValues: [...signingAlgValues],
  introspectionEndpointAuthSigningAlgValues: [...signingAlgValues],
  revocationEndpointAuthSigningAlgValues: [...signingAlgValues],

  idTokenSigningAlgValues: [...signingAlgValues, 'none'],
  requestObjectSigningAlgValues: [...signingAlgValues, 'none'],
  userinfoSigningAlgValues: [...signingAlgValues, 'none'],
  introspectionSigningAlgValues: [...signingAlgValues, 'none'],
  authorizationSigningAlgValues: [...signingAlgValues],

  idTokenEncryptionAlgValues: [...encryptionAlgValues],
  requestObjectEncryptionAlgValues: [...encryptionAlgValues],
  userinfoEncryptionAlgValues: [...encryptionAlgValues],
  introspectionEncryptionAlgValues: [...encryptionAlgValues],
  authorizationEncryptionAlgValues: [...encryptionAlgValues],

  idTokenEncryptionEncValues: [...encryptionEncValues],
  requestObjectEncryptionEncValues: [...encryptionEncValues],
  userinfoEncryptionEncValues: [...encryptionEncValues],
  introspectionEncryptionEncValues: [...encryptionEncValues],
  authorizationEncryptionEncValues: [...encryptionEncValues],

  dPoPSigningAlgValues: [...signingAlgValues].filter((alg) => !alg.startsWith('HS')),
};
