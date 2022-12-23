import { generateKeyPair } from 'jose';
import merge from 'lodash/merge.js';
import pull from 'lodash/pull.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, {
  requestObjects: { request: true },
  encryption: { enabled: true },
  introspection: { enabled: true },
  jwtIntrospection: { enabled: true },
  jwtUserinfo: { enabled: true },
  pushedAuthorizationRequests: { enabled: true },
});

pull(config.enabledJWA.requestObjectEncryptionAlgValues, 'RSA-OAEP-512');
pull(config.enabledJWA.requestObjectEncryptionEncValues, 'A192CBC-HS384');

export const keypair = await generateKeyPair('RS256');

export default {
  config,
  clients: [
    {
      client_id: 'client',
      client_secret: 'secret',
      redirect_uris: ['https://client.example.com/cb'],
      response_types: ['id_token token', 'code'],
      grant_types: ['implicit', 'authorization_code'],
      jwks: { keys: [keypair.publicKey.export({ format: 'jwk' })] },
      id_token_encrypted_response_alg: 'RSA-OAEP',
      // id_token_encrypted_response_enc: 'A128CBC-HS256',
      request_object_encryption_alg: 'RSA-OAEP',
      // request_object_encryption_enc: 'A128CBC-HS256',
      userinfo_signed_response_alg: 'RS256',
      userinfo_encrypted_response_alg: 'RSA-OAEP',
      // userinfo_encrypted_response_enc: 'A128CBC-HS256',
    },
    {
      client_id: 'clientSymmetric',
      client_secret: 'secret',
      redirect_uris: ['https://client.example.com/cb'],
      response_types: ['id_token'],
      grant_types: ['implicit'],
      id_token_encrypted_response_alg: 'A128KW',
    },
    {
      client_id: 'clientSymmetric-expired',
      client_secret: 'secret',
      redirect_uris: ['https://client.example.com/cb'],
      response_types: ['id_token'],
      grant_types: ['implicit'],
      client_secret_expires_at: 1,
      id_token_encrypted_response_alg: 'A128KW',
    },
    {
      client_id: 'clientSymmetric-dir',
      client_secret: 'secret',
      redirect_uris: ['https://client.example.com/cb'],
      response_types: ['id_token'],
      grant_types: ['implicit'],
      id_token_encrypted_response_alg: 'dir',
    },
    {
      client_id: 'clientRequestObjectSigningAlg',
      client_secret: 'secret',
      redirect_uris: ['https://client.example.com/cb'],
      response_types: ['code'],
      grant_types: ['authorization_code'],
      request_object_signing_alg: 'HS256',
    },
  ],
};
