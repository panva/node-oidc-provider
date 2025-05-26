import { randomBytes, generateKeyPairSync } from 'node:crypto';

import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

const attestationKeyPair = generateKeyPairSync('ed25519');

config.clientAuthMethods = [
  'attest_jwt_client_auth',
];
merge(config.features, {
  introspection: {
    enabled: true,
  },
  revocation: {
    enabled: true,
  },
  attestClientAuth: {
    enabled: true,
    challengeSecret: randomBytes(32),
    getAttestationSignaturePublicKey(ctx, iss, header, client) {
      if (iss === 'https://attester.example.com') {
        return client.jwks.keys[0];
      }
      throw new Error('unexpected attestation jwt issuer');
    },
  },
  deviceFlow: {
    enabled: true,
  },
  ciba: {
    enabled: true,
    validateRequestContext() {},
    verifyUserCode() {},
    triggerAuthenticationDevice() {},
    processLoginHint() {
      return 'sub';
    },
  },
});

export default {
  attestationKeyPair,
  config,
  clients: [{
    client_id: 'client',
    redirect_uris: ['https://rp.example.com/cb'],
    grant_types: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code', 'urn:openid:params:grant-type:ciba'],
    token_endpoint_auth_method: 'attest_jwt_client_auth',
    backchannel_token_delivery_mode: 'poll',
    jwks: {
      keys: [
        attestationKeyPair.publicKey.export({ format: 'jwk' }),
      ],
    },
  }],
};
