import { subtle } from 'node:crypto';

import { get, supportedAlgorithms } from '../../lib/helpers/hpke_algorithms.js';
import getConfig from '../default.config.js';
import keys from '../keys.js';

async function generate(alg, kid) {
  const keypair = await get(alg).suite.GenerateKeyPair(true);
  const privateJwk = await subtle.exportKey('jwk', keypair.privateKey);
  const publicJwk = await subtle.exportKey('jwk', keypair.publicKey);
  for (const jwk of [privateJwk, publicJwk]) {
    Object.assign(jwk, { alg, use: 'enc', kid });
    delete jwk.key_ops;
    delete jwk.ext;
  }
  return { ...keypair, privateJwk, publicJwk };
}

export const cases = await Promise.all(supportedAlgorithms.map(async (alg) => ({
  alg,
  clientId: `client-${alg}`,
  recipient: await generate(alg, `recipient-${alg}`),
  issuer: await generate(alg, `issuer-${alg}`),
})));

const config = getConfig();
Object.assign(config.features, {
  encryption: { enabled: true },
  hpke: { enabled: true, ack: 'draft-02' },
  requestObjects: { enabled: true },
  jwtUserinfo: { enabled: true },
  jwtResponseModes: { enabled: true },
  introspection: { enabled: true },
  jwtIntrospection: { enabled: true },
});
config.jwks = { keys: [...keys, ...cases.map(({ issuer }) => issuer.privateJwk)] };

export default {
  config,
  clients: cases.map(({ alg, clientId, recipient }) => ({
    client_id: clientId,
    client_secret: 'secret',
    redirect_uris: ['https://client.example.com/cb'],
    response_types: ['code', 'id_token token'],
    grant_types: ['authorization_code', 'implicit'],
    jwks: { keys: [recipient.publicJwk] },
    id_token_encrypted_response_alg: alg,
    userinfo_signed_response_alg: 'RS256',
    userinfo_encrypted_response_alg: alg,
    authorization_encrypted_response_alg: alg,
    introspection_signed_response_alg: 'RS256',
    introspection_encrypted_response_alg: alg,
    request_object_signing_alg: 'HS256',
    request_object_encryption_alg: alg,
  })),
};
