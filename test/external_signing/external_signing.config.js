import * as crypto from 'node:crypto';

import merge from 'lodash/merge.js';

import { ExternalSigningKey } from '../../lib/index.js';
import getConfig from '../default.config.js';

const es256 = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const es384 = crypto.generateKeyPairSync('ec', { namedCurve: 'P-384' });
const rs256 = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

const config = getConfig();

class ES256 extends ExternalSigningKey {
  constructor(kp) {
    super();
    this.kp = kp;
  }

  keyObject() {
    return this.kp.publicKey;
  }

  async sign(data) {
    return crypto.sign('sha256', data, {
      key: this.kp.privateKey,
      dsaEncoding: 'ieee-p1363',
    });
  }
}

class AsyncES384 extends ExternalSigningKey {
  constructor(kp) {
    super();
    this.kp = kp;
    this.jwk = kp.publicKey.export({ format: 'jwk' });
    this.keyObjectCalls = 0;
  }

  get kty() {
    return this.jwk.kty;
  }

  get crv() {
    return this.jwk.crv;
  }

  get e() {
    return this.jwk.e;
  }

  get n() {
    return this.jwk.n;
  }

  get x() {
    return this.jwk.x;
  }

  get y() {
    return this.jwk.y;
  }

  get pub() {
    return this.jwk.pub;
  }

  async keyObject() {
    this.keyObjectCalls++;
    return this.kp.publicKey;
  }

  async sign(data) {
    return crypto.sign('sha384', data, {
      key: this.kp.privateKey,
      dsaEncoding: 'ieee-p1363',
    });
  }
}

export const asyncExternalKey = new AsyncES384(es384);

merge(config.features, { externalSigningSupport: { enabled: true } });
merge(config, {
  jwks: {
    keys: [
      rs256.privateKey.export({ format: 'jwk' }),
      new ES256(es256),
      asyncExternalKey,
    ],
  },
});

export default {
  config,
  clients: [
    {
      client_id: 'client-sig-external',
      token_endpoint_auth_method: 'none',
      grant_types: ['implicit'],
      response_types: ['id_token'],
      redirect_uris: ['https://client.example.com/cb'],
      id_token_signed_response_alg: 'ES256',
    },
    {
      client_id: 'client-sig-internal',
      token_endpoint_auth_method: 'none',
      grant_types: ['implicit'],
      response_types: ['id_token'],
      redirect_uris: ['https://client.example.com/cb'],
      id_token_signed_response_alg: 'RS256',
    },
    {
      client_id: 'client-sig-external-async',
      token_endpoint_auth_method: 'none',
      grant_types: ['implicit'],
      response_types: ['id_token'],
      redirect_uris: ['https://client.example.com/cb'],
      id_token_signed_response_alg: 'ES384',
    },
  ],
};
