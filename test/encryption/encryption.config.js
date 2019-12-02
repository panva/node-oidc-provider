const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');
const pull = require('lodash/pull');
const jose = require('jose');

const config = cloneDeep(require('../default.config'));

merge(config.features, {
  requestObjects: { request: true },
  encryption: { enabled: true },
  introspection: { enabled: true },
  jwtIntrospection: { enabled: true },
});

pull(config.whitelistedJWA.requestObjectEncryptionAlgValues, 'RSA-OAEP');
pull(config.whitelistedJWA.requestObjectEncryptionEncValues, 'A192CBC-HS384');

const k = jose.JWK.generateSync('RSA', 2048);

const privKey = {
  keys: [k.toJWK(true)],
};

const pubKey = {
  keys: [k.toJWK(false)],
};

module.exports = {
  config,
  privKey,
  clients: [
    {
      client_id: 'client',
      client_secret: 'secret',
      redirect_uris: ['https://client.example.com/cb'],
      response_types: ['id_token token', 'code'],
      grant_types: ['implicit', 'authorization_code'],
      jwks: pubKey,
      id_token_encrypted_response_alg: 'RSA1_5',
      // id_token_encrypted_response_enc: 'A128CBC-HS256',
      request_object_encryption_alg: 'RSA1_5',
      // request_object_encryption_enc: 'A128CBC-HS256',
      userinfo_encrypted_response_alg: 'RSA1_5',
      // userinfo_encrypted_response_enc: 'A128CBC-HS256',
    },
    {
      client_id: 'clientSymmetric',
      client_secret: 'secret',
      redirect_uris: ['https://client.example.com/cb'],
      response_types: ['id_token'],
      grant_types: ['implicit'],
      id_token_encrypted_response_alg: 'PBES2-HS384+A192KW',
    },
    {
      client_id: 'clientSymmetric-expired',
      client_secret: 'secret',
      redirect_uris: ['https://client.example.com/cb'],
      response_types: ['id_token'],
      grant_types: ['implicit'],
      client_secret_expires_at: 1,
      id_token_encrypted_response_alg: 'PBES2-HS384+A192KW',
    },
    {
      client_id: 'clientSymmetric-dir',
      client_secret: 'secret',
      redirect_uris: ['https://client.example.com/cb'],
      response_types: ['id_token'],
      grant_types: ['implicit'],
      id_token_encrypted_response_alg: 'dir',
    },
  ],
};
