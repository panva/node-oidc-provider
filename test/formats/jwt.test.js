import { describe, before, afterEach, it } from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as util from 'node:util';

import { createSandbox } from 'sinon';
import base64url from 'base64url';

import ResourceServer from '../../lib/helpers/resource_server.js';
import epochTime from '../../lib/helpers/epoch_time.js';
import bootstrap from '../test_helper.js';

const sinon = createSandbox();

const generateKeyPair = util.promisify(crypto.generateKeyPair);
function decode(b64urljson) {
  return JSON.parse(base64url.decode(b64urljson));
}

describe('jwt format', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });
  afterEach(() => {
    fixture.provider.removeAllListeners();
  }, { timeout: 3000 });

  const accountId = 'account';
  const claims = {};
  const clientId = 'client';
  const grantId = 'grantid';
  const scope = 'openid';
  const sid = 'sid';
  const consumed = true;
  const acr = 'acr';
  const amr = ['amr'];
  const authTime = epochTime();
  const nonce = 'nonce';
  const redirectUri = 'https://rp.example.com/cb';
  const codeChallenge = 'codeChallenge';
  const codeChallengeMethod = 'codeChallengeMethod';
  const aud = 'foo';
  const gty = 'foo';
  const error = 'access_denied';
  const errorDescription = 'resource owner denied access';
  const params = { foo: 'bar' };
  const userCode = '1384-3217';
  const deviceInfo = { foo: 'bar' };
  const inFlight = true;
  const s256 = '_gPMqAT8BELhXwBa2nIT0OvdWtQCiF_g09nAyHhgCe0';
  const resource = 'urn:foo:bar';
  const policies = ['foo'];
  const sessionUid = 'foo';
  const expiresWithSession = false;
  const iiat = epochTime();
  const rotations = 1;
  const extra = { foo: 'bar' };
  const resourceServer = new ResourceServer(resource, {
    accessTokenFormat: 'jwt',
    audience: 'foo',
  });

  const fullPayload = {
    accountId, claims, clientId, grantId, scope, sid, consumed, acr, amr, authTime, nonce,
    redirectUri, codeChallenge, codeChallengeMethod, error, errorDescription, params,
    userCode, deviceInfo, gty, resource, policies, sessionUid, expiresWithSession,
    'x5t#S256': s256, inFlight, iiat, rotations, extra, jkt: s256, resourceServer,
  };

  afterEach(() => sinon.restore(), { timeout: 3000 });

  describe('Resource Server Configuration', () => {
    const fixture1 = Object.create(fixture);

    it('can be used to specify the signing algorithm', { timeout: 3000 }, async () => {
      const resourceServer = new ResourceServer(resource, {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: { alg: 'PS256' },
        },
      });

      const client = await fixture1.provider.Client.find(clientId);
      const token = new fixture1.provider.AccessToken({ client, ...fullPayload, resourceServer });
      const jwt = await token.save();

      const header = decode(jwt.split('.')[0]);
      ((actual) => { assert.ok('alg' in Object(actual)); assert.equal(actual.alg, 'PS256'); })(header);
    });

    it('uses the default idtokensigningalg by default (no jwt)', { timeout: 3000 }, async () => {
      const resourceServer = new ResourceServer(resource, {
        accessTokenFormat: 'jwt',
        audience: 'foo',
      });

      const client = await fixture1.provider.Client.find(clientId);
      const token = new fixture1.provider.AccessToken({ client, ...fullPayload, resourceServer });
      const jwt = await token.save();

      const header = decode(jwt.split('.')[0]);
      ((actual) => { assert.ok('alg' in Object(actual)); assert.equal(actual.alg, 'RS256'); })(header);
      ((actual) => { assert.ok('kid' in Object(actual)); assert.equal(actual.kid, i(fixture1.provider).keystore.selectForSign({ alg: 'RS256' })[0].kid); })(header);
    });

    it('uses the default idtokensigningalg by default (jwt)', { timeout: 3000 }, async () => {
      const resourceServer = new ResourceServer(resource, {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {},
      });

      const client = await fixture1.provider.Client.find(clientId);
      const token = new fixture1.provider.AccessToken({ client, ...fullPayload, resourceServer });
      const jwt = await token.save();

      const header = decode(jwt.split('.')[0]);
      ((actual) => { assert.ok('alg' in Object(actual)); assert.equal(actual.alg, 'RS256'); })(header);
      ((actual) => { assert.ok('kid' in Object(actual)); assert.equal(actual.kid, i(fixture1.provider).keystore.selectForSign({ alg: 'RS256' })[0].kid); })(header);
    });

    it('selects provider keys allowed for signing JWT access tokens', { timeout: 3000 }, async () => {
      const { keystore } = i(fixture1.provider);
      const original = [...keystore];
      const [source] = keystore.selectForSign({ alg: 'RS256' });
      const jwk = { ...source, key_ops: ['sign'] };

      keystore.clear();
      keystore.add(jwk);

      try {
        const resourceServer = new ResourceServer(resource, {
          accessTokenFormat: 'jwt',
          audience: 'foo',
          jwt: {
            sign: { alg: 'RS256', kid: jwk.kid },
          },
        });

        const client = await fixture1.provider.Client.find(clientId);
        const token = new fixture1.provider.AccessToken({ client, ...fullPayload, resourceServer });
        const jwt = await token.save();

        const header = decode(jwt.split('.')[0]);
        ((actual) => { assert.ok('kid' in Object(actual)); assert.equal(actual.kid, jwk.kid); })(header);
      } finally {
        keystore.clear();
        for (const key of original) {
          keystore.add(key);
        }
      }
    });

    it('can be used to specify the signing algorithm to be HMAC (buffer)', { timeout: 3000 }, async () => {
      const resourceServer = new ResourceServer(resource, {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: { alg: 'HS256', key: crypto.randomBytes(32) },
        },
      });

      const client = await fixture1.provider.Client.find(clientId);
      const token = new fixture1.provider.AccessToken({ client, ...fullPayload, resourceServer });
      const jwt = await token.save();

      const header = decode(jwt.split('.')[0]);
      ((actual) => { assert.ok('alg' in Object(actual)); assert.equal(actual.alg, 'HS256'); })(header);
      assert.ok(!('kid' in Object(header)));
    });

    it('can be used to specify the signing algorithm to be HMAC (CryptoKey)', { timeout: 3000 }, async () => {
      const resourceServer = new ResourceServer(resource, {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: { alg: 'HS256', key: await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, ['sign']) },
        },
      });

      const client = await fixture1.provider.Client.find(clientId);
      const token = new fixture1.provider.AccessToken({ client, ...fullPayload, resourceServer });
      const jwt = await token.save();

      const header = decode(jwt.split('.')[0]);
      ((actual) => { assert.ok('alg' in Object(actual)); assert.equal(actual.alg, 'HS256'); })(header);
      assert.ok(!('kid' in Object(header)));
    });

    it('kid must be a string (sign)', { timeout: 3000 }, async () => {
      const resourceServer = new ResourceServer(resource, {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: { alg: 'HS256', key: crypto.randomBytes(32), kid: 200 },
        },
      });

      const client = await fixture1.provider.Client.find(clientId);
      const token = new fixture1.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        assert.ok(err instanceof Error);
        assert.equal(err.message, 'jwt.sign.kid must be a string when provided');
        return true;
      });
    });

    it('kid must be a string (encrypt)', { timeout: 3000 }, async () => {
      const resourceServer = new ResourceServer(resource, {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          encrypt: {
            alg: 'dir',
            enc: 'A128GCM',
            key: crypto.randomBytes(16),
            kid: 200,
          },
        },
      });

      const client = await fixture1.provider.Client.find(clientId);
      const token = new fixture1.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        assert.ok(err instanceof Error);
        assert.equal(err.message, 'jwt.encrypt.kid must be a string when provided');
        return true;
      });
    });

    it('can be used to specify the signing algorithm to be HMAC (buffer w/ kid)', { timeout: 3000 }, async () => {
      const resourceServer = new ResourceServer(resource, {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: { alg: 'HS256', key: crypto.randomBytes(32), kid: 'feb-2020' },
        },
      });

      const client = await fixture1.provider.Client.find(clientId);
      const token = new fixture1.provider.AccessToken({ client, ...fullPayload, resourceServer });
      const jwt = await token.save();

      const header = decode(jwt.split('.')[0]);
      ((actual) => { assert.ok('kid' in Object(actual)); assert.equal(actual.kid, 'feb-2020'); })(header);
    });

    it('can be used to specify the signing algorithm to be HMAC (KeyObject)', { timeout: 3000 }, async () => {
      const resourceServer = new ResourceServer(resource, {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: { alg: 'HS256', key: crypto.createSecretKey(crypto.randomBytes(32)) },
        },
      });

      const client = await fixture1.provider.Client.find(clientId);
      const token = new fixture1.provider.AccessToken({ client, ...fullPayload, resourceServer });
      const jwt = await token.save();

      const header = decode(jwt.split('.')[0]);
      ((actual) => { assert.ok('alg' in Object(actual)); assert.equal(actual.alg, 'HS256'); })(header);
      assert.ok(!('kid' in Object(header)));
    });

    it('can be an encrypted JWT (Buffer)', { timeout: 3000 }, async () => {
      const resourceServer = new ResourceServer(resource, {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: false,
          encrypt: {
            alg: 'dir',
            enc: 'A128GCM',
            key: crypto.randomBytes(16),
          },
        },
      });

      const client = await fixture1.provider.Client.find(clientId);
      const token = new fixture1.provider.AccessToken({ client, ...fullPayload, resourceServer });
      const jwt = await token.save();

      const header = decode(jwt.split('.')[0]);
      ((actual) => { assert.ok('alg' in Object(actual)); assert.equal(actual.alg, 'dir'); })(header);
      ((actual) => { assert.ok('enc' in Object(actual)); assert.equal(actual.enc, 'A128GCM'); })(header);
      assert.ok(!('kid' in Object(header)));
      ((actual) => { assert.ok('typ' in Object(actual)); assert.equal(actual.typ, 'at+jwt'); })(header);
      ((actual) => { assert.ok('iss' in Object(actual)); assert.equal(actual.iss, fixture1.provider.issuer); })(header);
      ((actual) => { assert.ok('aud' in Object(actual)); assert.equal(actual.aud, 'foo'); })(header);
    });

    it('can be an encrypted JWT (KeyObject)', { timeout: 3000 }, async () => {
      const resourceServer = new ResourceServer(resource, {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: false,
          encrypt: {
            alg: 'dir',
            enc: 'A128GCM',
            key: crypto.generateKeySync('aes', { length: 128 }),
          },
        },
      });

      const client = await fixture1.provider.Client.find(clientId);
      const token = new fixture1.provider.AccessToken({ client, ...fullPayload, resourceServer });
      const jwt = await token.save();

      const header = decode(jwt.split('.')[0]);
      ((actual) => { assert.ok('alg' in Object(actual)); assert.equal(actual.alg, 'dir'); })(header);
      ((actual) => { assert.ok('enc' in Object(actual)); assert.equal(actual.enc, 'A128GCM'); })(header);
      assert.ok(!('kid' in Object(header)));
      ((actual) => { assert.ok('typ' in Object(actual)); assert.equal(actual.typ, 'at+jwt'); })(header);
      ((actual) => { assert.ok('iss' in Object(actual)); assert.equal(actual.iss, fixture1.provider.issuer); })(header);
      ((actual) => { assert.ok('aud' in Object(actual)); assert.equal(actual.aud, 'foo'); })(header);
    });

    it('can be an encrypted JWT (CryptoKey)', { timeout: 3000 }, async () => {
      const resourceServer = new ResourceServer(resource, {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: false,
          encrypt: {
            alg: 'dir',
            enc: 'A128GCM',
            key: await crypto.subtle.generateKey({ name: 'AES-GCM', length: 128 }, false, ['encrypt']),
          },
        },
      });

      const client = await fixture1.provider.Client.find(clientId);
      const token = new fixture1.provider.AccessToken({ client, ...fullPayload, resourceServer });
      const jwt = await token.save();

      const header = decode(jwt.split('.')[0]);
      ((actual) => { assert.ok('alg' in Object(actual)); assert.equal(actual.alg, 'dir'); })(header);
      ((actual) => { assert.ok('enc' in Object(actual)); assert.equal(actual.enc, 'A128GCM'); })(header);
      assert.ok(!('kid' in Object(header)));
      ((actual) => { assert.ok('typ' in Object(actual)); assert.equal(actual.typ, 'at+jwt'); })(header);
      ((actual) => { assert.ok('iss' in Object(actual)); assert.equal(actual.iss, fixture1.provider.issuer); })(header);
      ((actual) => { assert.ok('aud' in Object(actual)); assert.equal(actual.aud, 'foo'); })(header);
    });

    it('can be an encrypted JWT w/ kid', { timeout: 3000 }, async () => {
      const resourceServer = new ResourceServer(resource, {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: false,
          encrypt: {
            alg: 'dir',
            enc: 'A128GCM',
            key: crypto.randomBytes(16),
            kid: 'feb-2020',
          },
        },
      });

      const client = await fixture1.provider.Client.find(clientId);
      const token = new fixture1.provider.AccessToken({ client, ...fullPayload, resourceServer });
      const jwt = await token.save();

      const header = decode(jwt.split('.')[0]);
      ((actual) => { assert.ok('kid' in Object(actual)); assert.equal(actual.kid, 'feb-2020'); })(header);
    });

    it('can be a nested JWT (explicit)', { timeout: 3000 }, async () => {
      const resourceServer = new ResourceServer(resource, {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: {
            alg: 'PS256',
          },
          encrypt: {
            alg: 'ECDH-ES',
            enc: 'A128GCM',
            key: (await generateKeyPair('ec', { namedCurve: 'P-256' })).publicKey,
          },
        },
      });

      const client = await fixture1.provider.Client.find(clientId);
      const token = new fixture1.provider.AccessToken({ client, ...fullPayload, resourceServer });
      const jwt = await token.save();

      const header = decode(jwt.split('.')[0]);
      ((actual) => { assert.ok('alg' in Object(actual)); assert.equal(actual.alg, 'ECDH-ES'); })(header);
      ((actual) => { assert.ok('enc' in Object(actual)); assert.equal(actual.enc, 'A128GCM'); })(header);
      ((actual) => { assert.ok('cty' in Object(actual)); assert.equal(actual.cty, 'at+jwt'); })(header);
      ((actual) => { assert.ok('iss' in Object(actual)); assert.equal(actual.iss, fixture1.provider.issuer); })(header);
      ((actual) => { assert.ok('aud' in Object(actual)); assert.equal(actual.aud, 'foo'); })(header);
      assert.ok(!('kid' in Object(header)));
    });

    it('can be a nested JWT w/ kid', { timeout: 3000 }, async () => {
      const resourceServer = new ResourceServer(resource, {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: {
            alg: 'PS256',
          },
          encrypt: {
            alg: 'ECDH-ES',
            enc: 'A128GCM',
            key: (await generateKeyPair('ec', { namedCurve: 'P-256' })).publicKey,
            kid: 'feb-2020',
          },
        },
      });

      const client = await fixture1.provider.Client.find(clientId);
      const token = new fixture1.provider.AccessToken({ client, ...fullPayload, resourceServer });
      const jwt = await token.save();

      const header = decode(jwt.split('.')[0]);
      ((actual) => { assert.ok('kid' in Object(actual)); assert.equal(actual.kid, 'feb-2020'); })(header);
    });

    it('can be a nested JWT (implicit signing alg)', { timeout: 3000 }, async () => {
      const resourceServer = new ResourceServer(resource, {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: {},
          encrypt: {
            alg: 'ECDH-ES',
            enc: 'A128GCM',
            key: (await generateKeyPair('ec', { namedCurve: 'P-256' })).publicKey,
          },
        },
      });

      const client = await fixture1.provider.Client.find(clientId);
      const token = new fixture1.provider.AccessToken({ client, ...fullPayload, resourceServer });
      const jwt = await token.save();

      const header = decode(jwt.split('.')[0]);
      ((actual) => { assert.ok('alg' in Object(actual)); assert.equal(actual.alg, 'ECDH-ES'); })(header);
      ((actual) => { assert.ok('enc' in Object(actual)); assert.equal(actual.enc, 'A128GCM'); })(header);
      ((actual) => { assert.ok('cty' in Object(actual)); assert.equal(actual.cty, 'at+jwt'); })(header);
      ((actual) => { assert.ok('iss' in Object(actual)); assert.equal(actual.iss, fixture1.provider.issuer); })(header);
      ((actual) => { assert.ok('aud' in Object(actual)); assert.equal(actual.aud, 'foo'); })(header);
    });

    it('ensures "none" JWS algorithm cannot be used', { timeout: 3000 }, async () => {
      const resourceServer = new ResourceServer(resource, {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: {
            alg: 'none',
          },
        },
      });

      const client = await fixture1.provider.Client.find(clientId);
      const token = new fixture1.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        assert.ok(err instanceof Error);
        assert.equal(err.message, 'JWT Access Tokens may not use JWS algorithm "none"');
        return true;
      });
    });

    it('ensures HMAC JWS algorithms get a key', { timeout: 3000 }, async () => {
      const resourceServer = new ResourceServer(resource, {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: {
            alg: 'HS256',
          },
        },
      });

      const client = await fixture1.provider.Client.find(clientId);
      const token = new fixture1.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        assert.ok(err instanceof Error);
        assert.equal(err.message, 'missing jwt.sign.key Resource Server configuration');
        return true;
      });
    });

    it('ensures HMAC JWS algorithms get a secret key (1/2)', { timeout: 3000 }, async () => {
      const resourceServer = new ResourceServer(resource, {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: {
            alg: 'HS256',
            key: (await generateKeyPair('ec', { namedCurve: 'P-256' })).publicKey,
          },
        },
      });

      const client = await fixture1.provider.Client.find(clientId);
      const token = new fixture1.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        assert.ok(err instanceof Error);
        assert.equal(err.message, 'jwt.sign.key Resource Server configuration must be a secret (symmetric) key');
        return true;
      });
    });

    it('ensures HMAC JWS algorithms get a secret key (1/2)', { timeout: 3000 }, async () => {
      const resourceServer = new ResourceServer(resource, {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: {
            alg: 'HS256',
            key: (await generateKeyPair('ec', { namedCurve: 'P-256' })).privateKey,
          },
        },
      });

      const client = await fixture1.provider.Client.find(clientId);
      const token = new fixture1.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        assert.ok(err instanceof Error);
        assert.equal(err.message, 'jwt.sign.key Resource Server configuration must be a secret (symmetric) key');
        return true;
      });
    });

    it('ensures Asymmetric JWS algorithms have a key in the provider keystore', { timeout: 3000 }, async () => {
      const resourceServer = new ResourceServer(resource, {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: {
            alg: 'ES512',
          },
        },
      });

      const client = await fixture1.provider.Client.find(clientId);
      const token = new fixture1.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        assert.ok(err instanceof Error);
        assert.equal(err.message, 'resolved Resource Server jwt configuration has no corresponding key in the provider\'s keystore');
        return true;
      });
    });

    it('ensures JWE key is public or secret', { timeout: 3000 }, async () => {
      const resourceServer = new ResourceServer(resource, {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          encrypt: {
            alg: 'dir',
            enc: 'A128GCM',
            key: (await generateKeyPair('ec', { namedCurve: 'P-256' })).privateKey,
          },
        },
      });

      const client = await fixture1.provider.Client.find(clientId);
      const token = new fixture1.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        assert.ok(err instanceof Error);
        assert.equal(err.message, 'jwt.encrypt.key Resource Server configuration must be a secret (symmetric) or a public key');
        return true;
      });
    });

    it('ensures Nested JWT when JWE encryption is a public one', { timeout: 3000 }, async () => {
      const resourceServer = new ResourceServer(resource, {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          encrypt: {
            alg: 'ECDH-ES',
            enc: 'A128GCM',
            key: (await generateKeyPair('ec', { namedCurve: 'P-256' })).publicKey,
          },
        },
      });

      const client = await fixture1.provider.Client.find(clientId);
      const token = new fixture1.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        assert.ok(err instanceof Error);
        assert.equal(err.message, 'missing jwt.sign Resource Server configuration');
        return true;
      });
    });

    for (const prop of ['alg', 'enc', 'key']) {
      it(`ensures JWE Configuration has ${prop}`, { timeout: 3000 }, async () => {
        const resourceServer = new ResourceServer(resource, {
          accessTokenFormat: 'jwt',
          audience: 'foo',
          jwt: {
            encrypt: {
              alg: 'dir',
              enc: 'A128GCM',
              key: crypto.randomBytes(16),
            },
          },
        });

        delete resourceServer.jwt.encrypt[prop];

        const client = await fixture1.provider.Client.find(clientId);
        const token = new fixture1.provider.AccessToken({ client, ...fullPayload, resourceServer });
        return assert.rejects(token.save(), (err) => {
          assert.ok(err instanceof Error);
          assert.equal(err.message, `missing jwt.encrypt.${prop} Resource Server configuration`);
          return true;
        });
      });
    }
  });

  it('for AccessToken', { timeout: 3000 }, async () => {
    const upsert = sinon.spy(fixture.TestAdapter.for('AccessToken'), 'upsert');
    const client = await fixture.provider.Client.find(clientId);
    const token = new fixture.provider.AccessToken({ client, ...fullPayload });
    const issued = sinon.spy();
    fixture.provider.on('access_token.issued', issued);
    const jwt = await token.save();

    sinon.assert.notCalled(upsert);

    const { jti } = issued.getCall(0).args[0];
    const header = decode(jwt.split('.')[0]);
    ((actual) => { assert.ok('typ' in Object(actual)); assert.equal(actual.typ, 'at+jwt'); })(header);
    const { iat, exp, ...payload } = decode(jwt.split('.')[1]);
    assert.equal(typeof iat, 'number');
    assert.equal(typeof exp, 'number');
    assert.deepEqual(payload, {
      ...extra,
      aud,
      client_id: clientId,
      iss: fixture.provider.issuer,
      jti,
      scope,
      sub: accountId,
      cnf: {
        'x5t#S256': s256,
        jkt: s256,
      },
    });
  });

  it('for pairwise AccessToken', { timeout: 3000 }, async () => {
    const upsert = sinon.spy(fixture.TestAdapter.for('AccessToken'), 'upsert');
    const client = await fixture.provider.Client.find('pairwise');
    const token = new fixture.provider.AccessToken({ client, ...fullPayload });
    const issued = sinon.spy();
    fixture.provider.on('access_token.issued', issued);
    const jwt = await token.save();

    sinon.assert.notCalled(upsert);

    const { jti } = issued.getCall(0).args[0];
    const header = decode(jwt.split('.')[0]);
    ((actual) => { assert.ok('typ' in Object(actual)); assert.equal(actual.typ, 'at+jwt'); })(header);
    const { iat, exp, ...payload } = decode(jwt.split('.')[1]);
    assert.equal(typeof iat, 'number');
    assert.equal(typeof exp, 'number');
    assert.deepEqual(payload, {
      ...extra,
      aud,
      client_id: 'pairwise',
      iss: fixture.provider.issuer,
      jti,
      scope,
      sub: 'pairwise-sub',
      cnf: {
        'x5t#S256': s256,
        jkt: s256,
      },
    });
  });

  it('for ClientCredentials', { timeout: 3000 }, async () => {
    const upsert = sinon.spy(fixture.TestAdapter.for('ClientCredentials'), 'upsert');
    const client = await fixture.provider.Client.find(clientId);
    const token = new fixture.provider.ClientCredentials({ client, ...fullPayload });
    const issued = sinon.spy();
    fixture.provider.on('client_credentials.issued', issued);
    const jwt = await token.save();

    sinon.assert.notCalled(upsert);

    const { jti } = issued.getCall(0).args[0];
    const header = decode(jwt.split('.')[0]);
    ((actual) => { assert.ok('typ' in Object(actual)); assert.equal(actual.typ, 'at+jwt'); })(header);
    const { iat, exp, ...payload } = decode(jwt.split('.')[1]);
    assert.equal(typeof iat, 'number');
    assert.equal(typeof exp, 'number');
    assert.deepEqual(payload, {
      ...extra,
      aud,
      client_id: clientId,
      sub: clientId,
      iss: fixture.provider.issuer,
      jti,
      scope,
      cnf: {
        'x5t#S256': s256,
        jkt: s256,
      },
    });
  });

  describe('customizers', () => {
    const fixture2 = Object.create(fixture);

    afterEach(() => {
      i(fixture2.provider).configuration.formats.customizers.jwt = undefined;
    }, { timeout: 3000 });

    it('allows the payload to be extended', { timeout: 3000 }, async () => {
      const client = await fixture2.provider.Client.find(clientId);
      const accessToken = new fixture2.provider.AccessToken({ client, ...fullPayload });
      accessToken.resourceServer = resourceServer;
      i(fixture2.provider).configuration.formats.customizers.jwt = (_ctx, token, jwt) => {
        assert.equal(token, accessToken);
        assert.ok('payload' in Object(jwt));
        ((actual) => { assert.ok('header' in Object(actual)); assert.equal(actual.header, undefined); })(jwt);
        jwt.header = { customized: true, typ: 'foo' };
        jwt.payload.customized = true;
        jwt.payload.iss = 'foobar';
      };

      const jwt = await accessToken.save();
      const header = decode(jwt.split('.')[0]);
      ((actual) => { assert.ok('customized' in Object(actual)); assert.equal(actual.customized, true); })(header);
      ((actual) => { assert.ok('typ' in Object(actual)); assert.equal(actual.typ, 'foo'); })(header);
      const payload = decode(jwt.split('.')[1]);
      ((actual) => { assert.ok('customized' in Object(actual)); assert.equal(actual.customized, true); })(payload);
      ((actual) => { assert.ok('iss' in Object(actual)); assert.equal(actual.iss, 'foobar'); })(payload);
    });
  });
});
