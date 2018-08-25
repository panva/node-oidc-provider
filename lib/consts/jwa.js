const authSigningAlgValues = [
  'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512',
];

const signingAlgValues = [
  'none', ...authSigningAlgValues,
];

const encryptionAlgValues = [
  // asymmetric
  'RSA-OAEP', 'RSA1_5', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
  // symmetric
  'A128GCMKW', 'A192GCMKW', 'A256GCMKW', 'A128KW', 'A192KW', 'A256KW', 'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
];

const encryptionEncValues = [
  'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
];

module.exports = {
  tokenEndpointAuthSigningAlgValues: authSigningAlgValues.slice(),
  introspectionEndpointAuthSigningAlgValues: authSigningAlgValues.slice(),
  revocationEndpointAuthSigningAlgValues: authSigningAlgValues.slice(),

  idTokenSigningAlgValues: signingAlgValues.slice(),
  requestObjectSigningAlgValues: signingAlgValues.slice(),
  userinfoSigningAlgValues: signingAlgValues.slice(),
  introspectionSigningAlgValues: signingAlgValues.slice(),
  authorizationSigningAlgValues: authSigningAlgValues.slice(), // intended, no none

  idTokenEncryptionAlgValues: encryptionAlgValues.slice(),
  requestObjectEncryptionAlgValues: encryptionAlgValues.slice(),
  userinfoEncryptionAlgValues: encryptionAlgValues.slice(),
  introspectionEncryptionAlgValues: encryptionAlgValues.slice(),
  authorizationEncryptionAlgValues: encryptionAlgValues.slice(),

  idTokenEncryptionEncValues: encryptionEncValues.slice(),
  requestObjectEncryptionEncValues: encryptionEncValues.slice(),
  userinfoEncryptionEncValues: encryptionEncValues.slice(),
  introspectionEncryptionEncValues: encryptionEncValues.slice(),
  authorizationEncryptionEncValues: encryptionEncValues.slice(),
};
