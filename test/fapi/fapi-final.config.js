import crypto from 'node:crypto';

import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

export const keypair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });

merge(config.features, {
  fapi: {
    enabled: true,
  },
  jwtResponseModes: { enabled: true },
  requestObjects: {
    request: true,
    mode: 'strict',
  },
});
config.enabledJWA = {
  requestObjectSigningAlgValues: ['ES256'],
};

export default {
  config,
  clients: [{
    client_id: 'client',
    response_types: ['code id_token', 'code'],
    grant_types: ['implicit', 'authorization_code'],
    redirect_uris: ['https://client.example.com/cb'],
    token_endpoint_auth_method: 'none',
    jwks: {
      keys: [keypair.publicKey.export({ format: 'jwk' })],
    },
  }],
};
