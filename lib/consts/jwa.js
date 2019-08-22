const runtimeSupport = require('../helpers/runtime_support');

const signingAlgValues = [
  'HS256', 'HS384', 'HS512',
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  runtimeSupport.EdDSA ? 'EdDSA' : undefined,
].filter(Boolean);

const encryptionAlgValues = [
  // asymmetric kw
  'RSA-OAEP', runtimeSupport['RSA-OAEP-256'] ? 'RSA-OAEP-256' : false, 'RSA1_5',
  'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
  // symmetric kw
  'A128GCMKW', 'A192GCMKW', 'A256GCMKW', 'A128KW', 'A192KW', 'A256KW',
  'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
  // no kw
  'dir',
].filter(Boolean);

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
