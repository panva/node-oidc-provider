import getConfig from '../default.config.js';
import keys from '../keys.js';
import { cases } from '../encryption/hpke.config.js';

export { cases };

export const credentialResponse = {
  credentials: [{ credential: 'hpke-credential' }],
  notification_id: 'hpke-notification',
};

const config = getConfig();
config.jwks = { keys: [...keys, ...cases.map(({ issuer }) => issuer.privateJwk)] };
config.enabledJWA.credentialEncryptionAlgValues = cases.map(({ alg }) => alg);
config.features.encryption = { enabled: true };
config.features.hpke = { enabled: true, ack: 'draft-02' };
config.features.openid4vci = {
  enabled: true,
  ack: 'experimental-01',
  nonceSecret: Buffer.alloc(32),
  credentialRequestEncryption: true,
  credentialResponseEncryption: true,
  credentialConfigurationsSupported: {
    example: { format: 'example', scope: 'credential_scope' },
  },
  async issueCredential() {
    return structuredClone(credentialResponse);
  },
};

export default {
  config,
  client: {
    client_id: 'wallet',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    redirect_uris: ['https://wallet.example.com/cb'],
    token_endpoint_auth_method: 'none',
  },
};
