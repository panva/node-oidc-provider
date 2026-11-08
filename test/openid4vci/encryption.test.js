import { afterEach, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, hash, randomUUID } from 'node:crypto';

import {
  CompactEncrypt,
  SignJWT,
  calculateJwkThumbprint,
  compactDecrypt,
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
  importJWK,
} from 'jose';
import { createSandbox } from 'sinon';

import Provider from '../../lib/index.js';
import openidCredentialIssuer from '../../lib/actions/openid_credential_issuer.js';
import instance from '../../lib/helpers/weak_cache.js';
import { getCredentialRequestEncryptionKeys, parseCredentialRequest } from '../../lib/helpers/credential_encryption.js';
import bootstrap from '../test_helper.js';
import {
  credentialResponse,
  encryptionConfig,
  issuerJwk,
  issuerKeypair,
  nativeDecryptionKid,
  rsaIssuerJwk,
  rsaIssuerKeypair,
  unadvertisedKeypair,
} from './encryption.config.js';

const sinon = createSandbox();
const credentialRequest = { credential_configuration_id: 'example' };
const wallet = await generateKeyPair('ECDH-ES', { extractable: true });
const holder = await generateKeyPair('ES256', { extractable: true });
const otherHolder = await generateKeyPair('ES256', { extractable: true });
const walletJwk = {
  ...await exportJWK(wallet.publicKey),
  alg: 'ECDH-ES',
  kid: 'wallet-encryption',
};
const responseEncryption = { jwk: walletJwk, enc: 'A128GCM' };
const weakRsa = generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey.export({ format: 'jwk' });

describe('OpenID4VCI encryption configuration', () => {
  it('accepts supported request and response encryption settings', () => {
    assert.doesNotThrow(() => new Provider('https://issuer.example.com', encryptionConfig()));
  });

  it('normalizes true to optional encryption settings', () => {
    const config = encryptionConfig();
    config.features.openid4vci.credentialRequestEncryption = true;
    config.features.openid4vci.credentialResponseEncryption = true;
    const provider = new Provider('https://issuer.example.com', config);
    const { features } = instance(provider);
    assert.deepEqual(features.openid4vci.credentialRequestEncryption, { required: false });
    assert.deepEqual(features.openid4vci.credentialResponseEncryption, { required: false });
    const ctx = { oidc: { provider, issuer: provider.issuer, urlFor: (name) => `${provider.issuer}/${name}` } };
    openidCredentialIssuer(ctx);
    assert.equal(ctx.body.credential_request_encryption.encryption_required, false);
    assert.equal(ctx.body.credential_response_encryption.encryption_required, false);
  });

  for (const setting of [undefined, false]) {
    it(`disables encryption for ${setting === false ? 'false' : 'omitted'} settings`, () => {
      const config = encryptionConfig();
      config.features.encryption.enabled = false;
      config.jwks.keys = config.jwks.keys.slice(0, 1);
      if (setting === false) {
        config.features.openid4vci.credentialRequestEncryption = false;
        config.features.openid4vci.credentialResponseEncryption = false;
      } else {
        delete config.features.openid4vci.credentialRequestEncryption;
        delete config.features.openid4vci.credentialResponseEncryption;
      }
      const provider = new Provider('https://issuer.example.com', config);
      const { features } = instance(provider);
      assert.equal(features.openid4vci.credentialRequestEncryption, false);
      assert.equal(features.openid4vci.credentialResponseEncryption, false);
      const ctx = { oidc: { provider, issuer: provider.issuer, urlFor: (name) => `${provider.issuer}/${name}` } };
      openidCredentialIssuer(ctx);
      assert.ok(!Object.hasOwn(ctx.body, 'credential_request_encryption'));
      assert.ok(!Object.hasOwn(ctx.body, 'credential_response_encryption'));
    });
  }

  it('requires request encryption support for response encryption', () => {
    for (const setting of [true, { required: false }]) {
      const config = encryptionConfig();
      config.features.openid4vci.credentialRequestEncryption = false;
      config.features.openid4vci.credentialResponseEncryption = setting;
      assert.throws(() => new Provider('https://issuer.example.com', config), {
        message: 'features.openid4vci.credentialResponseEncryption requires credentialRequestEncryption',
      });
    }
  });

  for (const [member, setting] of [
    ['credential_request_encryption', 'credentialRequestEncryption'],
    ['credential_response_encryption', 'credentialResponseEncryption'],
  ]) {
    for (const configured of [false, true]) {
      it(`rejects ${member} in free-form metadata when encryption is ${configured ? 'configured' : 'disabled'}`, () => {
        const config = encryptionConfig();
        if (!configured) {
          delete config.features.openid4vci.credentialRequestEncryption;
          delete config.features.openid4vci.credentialResponseEncryption;
        }
        config.features.openid4vci.metadata = { [member]: { encryption_required: false } };
        assert.throws(() => new Provider('https://issuer.example.com', config), {
          message: `features.openid4vci.metadata.${member} is managed by ${setting}`,
        });
      });
    }
  }

  it('derives issuer encryption public keys from the provider keystore', () => {
    const provider = new Provider('https://issuer.example.com', encryptionConfig());
    const { keys } = getCredentialRequestEncryptionKeys(provider);
    assert.deepEqual(keys.map((key) => key.kid), [issuerJwk.kid, rsaIssuerJwk.kid, nativeDecryptionKid]);
    assert.ok(keys.every((key) => key.use === 'enc' && !key.d && !Object.hasOwn(key, 'key_ops')));
    const { jwks, keystore } = instance(provider);
    assert.equal(jwks.keys.find((key) => key.kid === nativeDecryptionKid).use, 'enc');
    assert.ok([...keystore].every((key) => key.key_ops === undefined));
  });

  it('requires encryption to be enabled', () => {
    const config = encryptionConfig();
    config.features.encryption.enabled = false;
    assert.throws(() => new Provider('https://issuer.example.com', config), /requires features\.encryption to be enabled/);
  });

  for (const alg of ['dir', 'A128KW', 'A128GCMKW']) {
    it(`rejects symmetric key management ${alg} in the credential algorithm policy`, () => {
      const config = encryptionConfig();
      config.enabledJWA.credentialEncryptionAlgValues = [alg];
      assert.throws(() => new Provider('https://issuer.example.com', config), /unsupported enabledJWA\.credentialEncryptionAlgValues algorithm/);
    });
  }

  it('selects issuer keys using enabledJWA.credentialEncryptionAlgValues', () => {
    const config = encryptionConfig();
    config.enabledJWA.credentialEncryptionAlgValues = ['RSA-OAEP-256'];
    const provider = new Provider('https://issuer.example.com', config);
    const { keys } = getCredentialRequestEncryptionKeys(provider);
    assert.deepEqual(keys.map((key) => key.kid), [rsaIssuerJwk.kid, nativeDecryptionKid]);
  });

  for (const member of ['credentialRequestEncryption', 'credentialResponseEncryption']) {
    for (const value of [null, [], 'true', 0]) {
      it(`rejects ${JSON.stringify(value)} ${member} settings`, () => {
        const config = encryptionConfig();
        config.features.openid4vci[member] = value;
        assert.throws(() => new Provider('https://issuer.example.com', config), {
          message: `features.openid4vci.${member} must be a boolean or an object`,
        });
      });
    }

    for (const [name, patch] of [
      ['a missing required policy', { required: undefined }],
      ['a non-boolean required policy', { required: 'false' }],
    ]) {
      it(`rejects ${name} in ${member}`, () => {
        const config = encryptionConfig();
        Object.assign(config.features.openid4vci[member], patch);
        assert.throws(() => new Provider('https://issuer.example.com', config), /features\.openid4vci\.credential(?:Request|Response)Encryption\./);
      });
    }
  }

  it('requires an eligible provider key to publish request encryption metadata', () => {
    const config = encryptionConfig();
    config.jwks.keys = config.jwks.keys.filter((key) => ![issuerJwk.kid, rsaIssuerJwk.kid, nativeDecryptionKid].includes(key.kid));
    const provider = new Provider('https://issuer.example.com', config);
    assert.throws(() => getCredentialRequestEncryptionKeys(provider), /features\.openid4vci\.credentialRequestEncryption/);
  });
});

describe('OpenID4VCI encryption', () => {
  const fixture = {};
  before(bootstrap(import.meta.url, fixture, { config: 'encryption' }), { timeout: 3000 });
  afterEach(() => sinon.restore());

  function feature() {
    return instance(fixture.provider).features.openid4vci;
  }

  async function accessToken(keypair) {
    const client = await fixture.provider.Client.find('wallet');
    const resource = `${fixture.provider.issuer}${fixture.suitePath('/credential')}`;
    const grant = new fixture.provider.Grant({ accountId: 'account', clientId: client.clientId });
    grant.addResourceScope(resource, 'credential_scope');
    const token = new fixture.provider.AccessToken({
      accountId: 'account',
      aud: resource,
      client,
      grantId: await grant.save(),
      scope: 'credential_scope',
    });
    if (keypair) {
      token.setThumbprint('jkt', await calculateJwkThumbprint(await exportJWK(keypair.publicKey)));
    }
    return token.save();
  }

  async function credentialProof(nonce) {
    return new SignJWT({ nonce, aud: fixture.provider.issuer })
      .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: await exportJWK(holder.publicKey) })
      .setIssuedAt()
      .sign(holder.privateKey);
  }

  async function proofRequest(nonce) {
    if (nonce === undefined) {
      ({ body: { c_nonce: nonce } } = await fixture.agent.post('/challenge').expect(200));
    }
    return {
      credential_configuration_id: 'proof_example',
      proofs: { jwt: [await credentialProof(nonce)] },
      credential_response_encryption: responseEncryption,
    };
  }

  async function dpopProof(token, keypair = holder) {
    return new SignJWT({
      htu: `${fixture.provider.issuer}${fixture.suitePath('/credential')}`,
      htm: 'POST',
      ath: hash('sha256', token, 'base64url'),
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: await exportJWK(keypair.publicKey) })
      .setIssuedAt()
      .setJti(randomUUID())
      .sign(keypair.privateKey);
  }

  async function encryptedRequest(body, {
    publicKey = issuerKeypair.publicKey,
    header = { alg: 'ECDH-ES', enc: 'A128GCM', kid: issuerJwk.kid },
    plaintext = JSON.stringify(body),
  } = {}) {
    return new CompactEncrypt(Buffer.from(plaintext)).setProtectedHeader(header).encrypt(publicKey);
  }

  async function post(body, { encrypted = true, ...options } = {}) {
    return fixture.agent.post('/credential')
      .set('Authorization', `Bearer ${await accessToken()}`)
      .type(encrypted ? 'application/jwt' : 'application/json')
      .send(encrypted ? await encryptedRequest(body, options) : body);
  }

  it('publishes request and response encryption capabilities', async () => {
    const { body } = await fixture.agent.get('/.well-known/openid-credential-issuer').expect(200);
    const { body: providerJwks } = await fixture.agent.get('/jwks').expect(200);
    const eligible = providerJwks.keys.filter((key) => key.use === 'enc'
      && instance(fixture.provider).configuration.enabledJWA.credentialEncryptionAlgValues.includes(key.alg));
    assert.deepEqual(body.credential_request_encryption, {
      enc_values_supported: instance(fixture.provider).configuration.enabledJWA.credentialEncryptionEncValues,
      encryption_required: feature().credentialRequestEncryption.required,
      jwks: { keys: eligible },
    });
    assert.deepEqual(body.credential_response_encryption, {
      alg_values_supported: instance(fixture.provider).configuration.enabledJWA.credentialEncryptionAlgValues,
      enc_values_supported: instance(fixture.provider).configuration.enabledJWA.credentialEncryptionEncValues,
      encryption_required: feature().credentialResponseEncryption.required,
    });
    assert.ok(!Object.hasOwn(body.credential_request_encryption, 'zip_values_supported'));
    assert.ok(!Object.hasOwn(body.credential_response_encryption, 'zip_values_supported'));
    assert.deepEqual(eligible.map((key) => key.kid), [issuerJwk.kid, rsaIssuerJwk.kid, nativeDecryptionKid]);
    assert.ok(eligible.every((key) => !('d' in key) && !('key_ops' in key)));
    assert.ok(!eligible.some((key) => key.kid === 'unadvertised-encryption'));
  });

  it('preserves additional issuer metadata alongside generated encryption capabilities', async () => {
    sinon.stub(feature(), 'metadata').value({ display: [{ name: 'Credential Issuer' }] });
    const { body } = await fixture.agent.get('/.well-known/openid-credential-issuer').expect(200);
    assert.deepEqual(body.display, [{ name: 'Credential Issuer' }]);
    assert.deepEqual(body.credential_response_encryption, {
      alg_values_supported: ['ECDH-ES', 'RSA-OAEP-256'],
      enc_values_supported: ['A128GCM'],
      encryption_required: false,
    });
    assert.ok(!Object.hasOwn(body, 'credentialRequestEncryption'));
    assert.ok(!Object.hasOwn(body, 'credentialResponseEncryption'));
  });

  it('does not advertise or accept encryption when its settings are false', async () => {
    sinon.stub(feature(), 'credentialRequestEncryption').value(false);
    sinon.stub(feature(), 'credentialResponseEncryption').value(false);
    const { body } = await fixture.agent.get('/.well-known/openid-credential-issuer').expect(200);
    assert.ok(!Object.hasOwn(body, 'credential_request_encryption'));
    assert.ok(!Object.hasOwn(body, 'credential_response_encryption'));
    assert.equal((await post(credentialRequest, { encrypted: false })).status, 200);
    const response = await post(credentialRequest);
    assert.equal(response.status, 400);
    assert.equal(response.body.error, 'invalid_credential_request');
    const encryptedResponse = await post({
      ...credentialRequest,
      credential_response_encryption: responseEncryption,
    }, { encrypted: false });
    assert.equal(encryptedResponse.status, 400);
    assert.equal(encryptedResponse.body.error, 'invalid_encryption_parameters');
  });

  for (const kid of [issuerJwk.kid, rsaIssuerJwk.kid, nativeDecryptionKid]) {
    it(`encrypts a credential request using the discovered ${kid} public key`, async () => {
      const { body } = await fixture.agent.get('/.well-known/openid-credential-issuer').expect(200);
      const publicKey = body.credential_request_encryption.jwks.keys.find((key) => key.kid === kid);
      const response = await post(credentialRequest, {
        publicKey: await importJWK(publicKey, publicKey.alg),
        header: { alg: publicKey.alg, enc: 'A128GCM', kid },
      });
      assert.equal(response.status, 200);
      assert.deepEqual(response.body, credentialResponse);
      const privateKey = [...instance(fixture.provider).keystore].find((key) => key.kid === kid);
      assert.ok(!Object.hasOwn(privateKey, 'key_ops'));
    });
  }

  it('accepts JSON when true enables optional encryption', async () => {
    const response = await post(credentialRequest, { encrypted: false });
    assert.equal(response.status, 200);
    assert.match(response.headers['content-type'], /^application\/json/);
    assert.deepEqual(response.body, credentialResponse);
  });

  it('accepts encrypted requests when true enables encryption', async () => {
    const response = await post(credentialRequest);
    assert.equal(response.status, 200);
    assert.deepEqual(response.body, credentialResponse);
  });

  it('advertises and accepts newly enabled content encryption algorithms', async () => {
    const { enabledJWA } = instance(fixture.provider).configuration;
    sinon.stub(enabledJWA, 'credentialEncryptionEncValues').value(['A128GCM', 'A256GCM']);
    const { body } = await fixture.agent.get('/.well-known/openid-credential-issuer').expect(200);
    assert.deepEqual(body.credential_request_encryption.enc_values_supported, ['A128GCM', 'A256GCM']);
    assert.deepEqual(body.credential_response_encryption.enc_values_supported, ['A128GCM', 'A256GCM']);
    const response = await post({
      ...credentialRequest,
      credential_response_encryption: { ...responseEncryption, enc: 'A256GCM' },
    }, {
      header: { alg: 'ECDH-ES', enc: 'A256GCM', kid: issuerJwk.kid },
    });
    assert.equal(response.status, 200);
    const { plaintext, protectedHeader } = await compactDecrypt(response.text, wallet.privateKey);
    assert.equal(protectedHeader.enc, 'A256GCM');
    assert.deepEqual(JSON.parse(Buffer.from(plaintext).toString()), credentialResponse);
  });

  it('rejects a recipient algorithm removed from enabledJWA before issuance', async () => {
    const { enabledJWA } = instance(fixture.provider).configuration;
    sinon.stub(enabledJWA, 'credentialEncryptionAlgValues').value(['ECDH-ES']);
    const { body } = await fixture.agent.get('/.well-known/openid-credential-issuer').expect(200);
    assert.deepEqual(body.credential_response_encryption.alg_values_supported, ['ECDH-ES']);
    assert.deepEqual(body.credential_request_encryption.jwks.keys.map((key) => key.kid), [issuerJwk.kid]);
    const spy = sinon.spy(feature(), 'issueCredential');
    const response = await post({
      ...credentialRequest,
      credential_response_encryption: { jwk: rsaIssuerJwk, enc: 'A128GCM' },
    });
    assert.equal(response.status, 400);
    assert.equal(response.body.error, 'invalid_encryption_parameters');
    assert.equal(spy.callCount, 0);
  });

  it('rejects compressed credential requests before issuing credentials', async () => {
    const spy = sinon.spy(feature(), 'issueCredential');
    const response = await post(credentialRequest, {
      header: { alg: 'ECDH-ES', enc: 'A128GCM', kid: issuerJwk.kid, zip: 'DEF' },
    });
    assert.equal(response.status, 400);
    assert.equal(response.body.error, 'invalid_credential_request');
    assert.equal(spy.callCount, 0);
  });

  it('rejects compressed credential responses before issuing credentials', async () => {
    const spy = sinon.spy(feature(), 'issueCredential');
    const response = await post({
      ...credentialRequest,
      credential_response_encryption: { ...responseEncryption, zip: 'DEF' },
    });
    assert.equal(response.status, 400);
    assert.equal(response.body.error, 'invalid_encryption_parameters');
    assert.equal(spy.callCount, 0);
  });

  it('decrypts RSA requests using the provider encryption key', async () => {
    const response = await post(credentialRequest, {
      publicKey: rsaIssuerKeypair.publicKey,
      header: { alg: rsaIssuerJwk.alg, enc: 'A128GCM', kid: rsaIssuerJwk.kid },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(response.body, credentialResponse);
  });

  it('encrypts to an RSA recipient with encryption key operations', async () => {
    const jwk = { ...rsaIssuerJwk, use: 'enc', key_ops: ['encrypt', 'wrapKey'] };
    const response = await post({ ...credentialRequest, credential_response_encryption: { jwk, enc: 'A128GCM' } });
    assert.equal(response.status, 200);
    const { plaintext } = await compactDecrypt(response.text, rsaIssuerKeypair.privateKey);
    assert.deepEqual(JSON.parse(Buffer.from(plaintext).toString()), credentialResponse);
  });

  it('encrypts to an X25519 recipient', async () => {
    const recipient = await generateKeyPair('ECDH-ES', { crv: 'X25519', extractable: true });
    const jwk = { ...await exportJWK(recipient.publicKey), alg: 'ECDH-ES', key_ops: [] };
    const response = await post({ ...credentialRequest, credential_response_encryption: { jwk, enc: 'A128GCM' } });
    assert.equal(response.status, 200);
    const { plaintext } = await compactDecrypt(response.text, recipient.privateKey);
    assert.deepEqual(JSON.parse(Buffer.from(plaintext).toString()), credentialResponse);
  });

  for (const alg of ['ECDH-ES', 'RSA-OAEP-256']) {
    it(`encrypts the complete credential response using ${alg}`, { timeout: 3000 }, async () => {
      const recipient = alg === 'ECDH-ES' ? wallet : await generateKeyPair(alg, { extractable: true });
      const jwk = { ...await exportJWK(recipient.publicKey), alg, kid: 'recipient-key' };
      const response = await post({ ...credentialRequest, credential_response_encryption: { jwk, enc: 'A128GCM' } });
      assert.equal(response.status, 200);
      assert.match(response.headers['content-type'], /^application\/jwt/);
      assert.match(response.headers['cache-control'], /no-store/);
      const { plaintext, protectedHeader } = await compactDecrypt(response.text, recipient.privateKey);
      assert.deepEqual(protectedHeader, { alg, enc: 'A128GCM', kid: 'recipient-key', ...(alg === 'ECDH-ES' ? { epk: protectedHeader.epk } : {}) });
      assert.deepEqual(JSON.parse(Buffer.from(plaintext).toString()), credentialResponse);
    });
  }

  it('does not invent a recipient key ID', async () => {
    const jwk = { ...walletJwk };
    delete jwk.kid;
    const response = await post({ ...credentialRequest, credential_response_encryption: { jwk, enc: 'A128GCM' } });
    assert.equal(response.status, 200);
    assert.ok(!('kid' in decodeProtectedHeader(response.text)));
  });

  it('passes the decrypted request to the issuance callback', async () => {
    const spy = sinon.spy(feature(), 'issueCredential');
    const body = { ...credentialRequest, credential_response_encryption: responseEncryption };
    const response = await post(body);
    assert.equal(response.status, 200);
    assert.equal(spy.callCount, 1);
    assert.deepEqual(spy.firstCall.args[1].body, body);
  });

  it('validates JWT holder proofs and nonce inside encrypted credential requests', async () => {
    const spy = sinon.spy(feature(), 'issueCredential');
    const body = await proofRequest();
    const response = await post(body);
    assert.equal(response.status, 200);
    assert.equal(spy.callCount, 1);
    assert.deepEqual(spy.firstCall.args[1].proofs, body.proofs);
    const { plaintext } = await compactDecrypt(response.text, wallet.privateKey);
    assert.deepEqual(JSON.parse(Buffer.from(plaintext).toString()), credentialResponse);
  });

  it('rejects an invalid JWT holder proof nonce before issuing credentials', async () => {
    const spy = sinon.spy(feature(), 'issueCredential');
    const response = await post(await proofRequest('invalid'));
    assert.equal(response.status, 400);
    assert.match(response.headers['content-type'], /^application\/json/);
    assert.equal(response.body.error, 'invalid_nonce');
    assert.equal(spy.callCount, 0);
  });

  it('accepts DPoP-bound tokens for encrypted requests and rejects DPoP replay', async () => {
    const token = await accessToken(holder);
    const dpop = await dpopProof(token);
    const encrypted = await encryptedRequest(await proofRequest());
    const spy = sinon.spy(feature(), 'issueCredential');
    const send = () => fixture.agent.post('/credential')
      .set('Authorization', `DPoP ${token}`)
      .set('DPoP', dpop)
      .type('application/jwt')
      .send(encrypted);
    const response = await send();
    assert.equal(response.status, 200);
    const { plaintext } = await compactDecrypt(response.text, wallet.privateKey);
    assert.deepEqual(JSON.parse(Buffer.from(plaintext).toString()), credentialResponse);

    const error = sinon.spy();
    fixture.provider.once('credential.error', error);
    const replay = await send();
    assert.equal(replay.status, 401);
    assert.equal(replay.body.error, 'invalid_token');
    assert.equal(error.firstCall.args[1].error_detail, 'DPoP proof JWT Replay detected');
    assert.equal(spy.callCount, 1);
  });

  it('rejects the wrong DPoP key for an encrypted request before issuing credentials', async () => {
    const token = await accessToken(holder);
    const spy = sinon.spy(feature(), 'issueCredential');
    const response = await fixture.agent.post('/credential')
      .set('Authorization', `DPoP ${token}`)
      .set('DPoP', await dpopProof(token, otherHolder))
      .type('application/jwt')
      .send(await encryptedRequest(await proofRequest()));
    assert.equal(response.status, 401);
    assert.equal(response.body.error, 'invalid_token');
    assert.equal(spy.callCount, 0);
  });

  for (const contentType of ['application/json', 'application/jwt']) {
    for (const token of [undefined, 'unknown-access-token']) {
      it(`authenticates ${token ? 'unknown' : 'missing'} tokens before parsing a malformed ${contentType} body`, async () => {
        const spy = sinon.spy(feature(), 'issueCredential');
        const request = fixture.agent.post('/credential').type(contentType);
        if (token) request.set('Authorization', `Bearer ${token}`);
        const response = await request.send('invalid');
        assert.equal(response.status, 401);
        assert.equal(response.body.error, 'invalid_token');
        assert.equal(spy.callCount, 0);
      });
    }
  }

  it('requires an encrypted request when response encryption is requested', async () => {
    const spy = sinon.spy(feature(), 'issueCredential');
    const response = await post({ ...credentialRequest, credential_response_encryption: responseEncryption }, { encrypted: false });
    assert.equal(response.status, 400);
    assert.equal(response.body.error, 'invalid_encryption_parameters');
    assert.equal(spy.callCount, 0);
  });

  it('enforces required request encryption', async () => {
    sinon.stub(feature().credentialRequestEncryption, 'required').value(true);
    const spy = sinon.spy(feature(), 'issueCredential');
    const response = await post(credentialRequest, { encrypted: false });
    assert.equal(response.status, 400);
    assert.equal(response.body.error, 'invalid_credential_request');
    assert.equal(spy.callCount, 0);
    assert.equal((await post(credentialRequest)).status, 200);
  });

  it('enforces required response encryption', async () => {
    sinon.stub(feature().credentialResponseEncryption, 'required').value(true);
    const spy = sinon.spy(feature(), 'issueCredential');
    const response = await post(credentialRequest);
    assert.equal(response.status, 400);
    assert.equal(response.body.error, 'invalid_encryption_parameters');
    assert.equal(spy.callCount, 0);
    assert.equal((await post({ ...credentialRequest, credential_response_encryption: responseEncryption })).status, 200);
  });

  for (const [name, value] of [
    ['a null encryption object', null],
    ['an array encryption object', []],
    ['a missing recipient key', { enc: 'A128GCM' }],
    ['a null recipient key', { jwk: null, enc: 'A128GCM' }],
    ['a symmetric recipient key', { jwk: { kty: 'oct', k: 'c2VjcmV0', alg: 'dir' }, enc: 'A128GCM' }],
    ['a private recipient key', { jwk: { ...walletJwk, d: 'private' }, enc: 'A128GCM' }],
    ['a recipient key without alg', { jwk: { ...walletJwk, alg: undefined }, enc: 'A128GCM' }],
    ['an unsupported key algorithm', { jwk: { ...walletJwk, alg: 'ECDH-ES+A128KW' }, enc: 'A128GCM' }],
    ['an incompatible key algorithm', { jwk: { ...walletJwk, alg: 'RSA-OAEP-256' }, enc: 'A128GCM' }],
    ['a signing recipient key', { jwk: { ...walletJwk, use: 'sig' }, enc: 'A128GCM' }],
    ['a recipient key with signing operations', { jwk: { ...walletJwk, key_ops: ['verify'] }, enc: 'A128GCM' }],
    ['invalid recipient public material', { jwk: { ...walletJwk, x: 'invalid' }, enc: 'A128GCM' }],
    ['a low-order X25519 recipient', { jwk: { kty: 'OKP', crv: 'X25519', x: Buffer.alloc(32).toString('base64url'), alg: 'ECDH-ES' }, enc: 'A128GCM' }],
    ['a weak RSA recipient', { jwk: { ...weakRsa, alg: 'RSA-OAEP-256' }, enc: 'A128GCM' }],
    ['a missing content encryption algorithm required by jose', { jwk: walletJwk }],
    ['an unsupported content encryption algorithm', { jwk: walletJwk, enc: 'A256GCM' }],
    ['an unsupported compression request', { ...responseEncryption, zip: 'GZIP' }],
  ]) {
    it(`rejects ${name} before issuing credentials`, async () => {
      const spy = sinon.spy(feature(), 'issueCredential');
      const response = await post({ ...credentialRequest, credential_response_encryption: value });
      assert.equal(response.status, 400);
      assert.equal(response.body.error, 'invalid_encryption_parameters');
      assert.equal(spy.callCount, 0);
    });
  }

  for (const [name, options] of [
    ['an unsupported key algorithm', { header: { alg: 'ECDH-ES+A128KW', enc: 'A128GCM', kid: issuerJwk.kid } }],
    ['an unsupported content encryption algorithm', { header: { alg: 'ECDH-ES', enc: 'A256GCM', kid: issuerJwk.kid } }],
    ['an unknown key ID', { header: { alg: 'ECDH-ES', enc: 'A128GCM', kid: 'unknown' } }],
    ['a missing key ID', { header: { alg: 'ECDH-ES', enc: 'A128GCM' } }],
    ['an unadvertised provider key', { publicKey: unadvertisedKeypair.publicKey, header: { alg: 'ECDH-ES', enc: 'A128GCM', kid: 'unadvertised-encryption' } }],
    ['invalid decrypted JSON', { plaintext: 'invalid' }],
    ['a decrypted array', { plaintext: '[]' }],
  ]) {
    it(`rejects requests with ${name}`, async () => {
      const spy = sinon.spy(feature(), 'issueCredential');
      const response = await post(credentialRequest, options);
      assert.equal(response.status, 400);
      assert.equal(response.body.error, 'invalid_credential_request');
      assert.equal(spy.callCount, 0);
    });
  }

  it('rejects malformed encrypted requests', async () => {
    const response = await fixture.agent.post('/credential')
      .set('Authorization', `Bearer ${await accessToken()}`)
      .type('application/jwt')
      .send('invalid');
    assert.equal(response.status, 400);
    assert.equal(response.body.error, 'invalid_credential_request');
  });

  it('rejects encrypted requests exceeding the body size limit', async () => {
    const spy = sinon.spy(feature(), 'issueCredential');
    const response = await post({ ...credentialRequest, padding: 'a'.repeat(56 * 1024) });
    assert.equal(response.status, 400);
    assert.equal(response.body.error, 'invalid_credential_request');
    assert.equal(spy.callCount, 0);
  });

  it('accepts an upstream parsed raw JWT body', async () => {
    const body = await encryptedRequest(credentialRequest);
    for (const raw of [body, Buffer.from(body)]) {
      const ctx = {
        oidc: { provider: fixture.provider },
        is: (type) => type === 'application/jwt',
        req: { readable: false, body: raw },
        request: {},
      };
      const next = sinon.spy();
      await parseCredentialRequest(ctx, next);
      assert.deepEqual(ctx.oidc.body, credentialRequest);
      assert.equal(next.callCount, 1);
    }
  });

  it('returns errors as JSON even when response encryption was requested', async () => {
    const response = await post({
      credential_configuration_id: 'unknown',
      credential_response_encryption: responseEncryption,
    });
    assert.equal(response.status, 400);
    assert.match(response.headers['content-type'], /^application\/json/);
    assert.equal(response.body.error, 'unknown_credential_configuration');
  });

  it('rejects tampered encrypted requests', async () => {
    const parts = (await encryptedRequest(credentialRequest)).split('.');
    parts[4] = Buffer.alloc(16).toString('base64url');
    const spy = sinon.spy(feature(), 'issueCredential');
    const response = await fixture.agent.post('/credential')
      .set('Authorization', `Bearer ${await accessToken()}`)
      .type('application/jwt')
      .send(parts.join('.'));
    assert.equal(response.status, 400);
    assert.equal(response.body.error, 'invalid_credential_request');
    assert.equal(spy.callCount, 0);
  });
});
