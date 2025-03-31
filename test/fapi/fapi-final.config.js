import { strict as assert } from 'node:assert';

import { generateKeyPair, exportJWK } from 'jose';
import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

export const keypair = await generateKeyPair('ES256');

merge(config.features, {
  fapi: {
    enabled: true,
    profile(ctx, client) {
      assert(ctx, 'ctx not provided in fapi.profile');
      assert(client, 'client not provided in fapi.profile');
      return '1.0 Final';
    },
  },
  jwtResponseModes: { enabled: true },
  requestObjects: {
    enabled: true,
  },
});
config.enabledJWA = {
  requestObjectSigningAlgValues: ['ES256'],
};
config.acceptQueryParamAccessTokens = true;

export default {
  config,
  clients: [{
    client_id: 'client',
    client_secret: 'secret',
    response_types: ['code id_token', 'code'],
    grant_types: ['implicit', 'authorization_code'],
    redirect_uris: ['https://client.example.com/cb'],
    jwks: {
      keys: [await exportJWK(keypair.publicKey)],
    },
  }],
};
