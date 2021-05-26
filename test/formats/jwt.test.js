/* eslint-disable no-shadow */
/* eslint-disable no-param-reassign */
const { strict: assert } = require('assert');
const crypto = require('crypto');
const util = require('util');

const sinon = require('sinon').createSandbox();
const { expect } = require('chai');
const base64url = require('base64url');

const epochTime = require('../../lib/helpers/epoch_time');
const bootstrap = require('../test_helper');

const generateKeyPair = util.promisify(crypto.generateKeyPair);
function decode(b64urljson) {
  return JSON.parse(base64url.decode(b64urljson));
}

describe('jwt format', () => {
  before(bootstrap(__dirname));
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
  const resourceServer = {
    accessTokenFormat: 'jwt',
    audience: 'foo',
  };

  /* eslint-disable object-property-newline */
  const fullPayload = {
    accountId, claims, clientId, grantId, scope, sid, consumed, acr, amr, authTime, nonce,
    redirectUri, codeChallenge, codeChallengeMethod, error, errorDescription, params,
    userCode, deviceInfo, gty, resource, policies, sessionUid, expiresWithSession,
    'x5t#S256': s256, inFlight, iiat, rotations, extra, jkt: s256, resourceServer,
  };
  /* eslint-enable object-property-newline */

  afterEach(sinon.restore);

  describe('Resource Server Configuration', () => {
    it('can be used to specify the signing algorithm', async function () {
      const resourceServer = {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: { alg: 'PS256' },
        },
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      const jwt = await token.save();

      const header = decode(jwt.split('.')[0]);
      expect(header).to.have.property('alg', 'PS256');
    });

    it('uses the default idtokensigningalg by default (no jwt)', async function () {
      const resourceServer = {
        accessTokenFormat: 'jwt',
        audience: 'foo',
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      const jwt = await token.save();

      const header = decode(jwt.split('.')[0]);
      expect(header).to.have.property('alg', 'RS256');
      expect(header).to.have.property('kid', i(this.provider).keystore.selectForSign({ alg: 'RS256' })[0].kid);
    });

    it('uses the default idtokensigningalg by default (jwt)', async function () {
      const resourceServer = {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {},
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      const jwt = await token.save();

      const header = decode(jwt.split('.')[0]);
      expect(header).to.have.property('alg', 'RS256');
      expect(header).to.have.property('kid', i(this.provider).keystore.selectForSign({ alg: 'RS256' })[0].kid);
    });

    it('can be used to specify the signing algorithm to be HMAC (buffer)', async function () {
      const resourceServer = {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: { alg: 'HS256', key: crypto.randomBytes(32) },
        },
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      const jwt = await token.save();

      const header = decode(jwt.split('.')[0]);
      expect(header).to.have.property('alg', 'HS256');
      expect(header).not.to.have.property('kid');
    });

    it('kid must be a string (sign)', async function () {
      const resourceServer = {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: { alg: 'HS256', key: crypto.randomBytes(32), kid: 200 },
        },
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('jwt.sign.kid must be a string when provided');
        return true;
      });
    });

    it('kid must be a string (encrypt)', async function () {
      const resourceServer = {
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
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('jwt.encrypt.kid must be a string when provided');
        return true;
      });
    });

    it('can be used to specify the signing algorithm to be HMAC (buffer w/ kid)', async function () {
      const resourceServer = {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: { alg: 'HS256', key: crypto.randomBytes(32), kid: 'feb-2020' },
        },
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      const jwt = await token.save();

      const header = decode(jwt.split('.')[0]);
      expect(header).to.have.property('kid', 'feb-2020');
    });

    it('can be used to specify the signing algorithm to be HMAC (KeyObject)', async function () {
      const resourceServer = {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: { alg: 'HS256', key: crypto.createSecretKey(crypto.randomBytes(32)) },
        },
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      const jwt = await token.save();

      const header = decode(jwt.split('.')[0]);
      expect(header).to.have.property('alg', 'HS256');
      expect(header).not.to.have.property('kid');
    });

    it('can be an encrypted JWT', async function () {
      const resourceServer = {
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
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      const jwt = await token.save();

      const header = decode(jwt.split('.')[0]);
      expect(header).to.have.property('alg', 'dir');
      expect(header).to.have.property('enc', 'A128GCM');
      expect(header).not.to.have.property('kid');
      expect(header).to.have.property('typ', 'at+jwt');
      expect(header).to.have.property('iss', this.provider.issuer);
      expect(header).to.have.property('aud', 'foo');
    });

    it('can be an encrypted JWT w/ kid', async function () {
      const resourceServer = {
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
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      const jwt = await token.save();

      const header = decode(jwt.split('.')[0]);
      expect(header).to.have.property('kid', 'feb-2020');
    });

    it('can be a nested JWT (explicit)', async function () {
      const resourceServer = {
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
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      const jwt = await token.save();

      const header = decode(jwt.split('.')[0]);
      expect(header).to.have.property('alg', 'ECDH-ES');
      expect(header).to.have.property('enc', 'A128GCM');
      expect(header).to.have.property('cty', 'at+jwt');
      expect(header).to.have.property('iss', this.provider.issuer);
      expect(header).to.have.property('aud', 'foo');
      expect(header).not.to.have.property('kid');
    });

    it('can be a nested JWT w/ kid', async function () {
      const resourceServer = {
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
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      const jwt = await token.save();

      const header = decode(jwt.split('.')[0]);
      expect(header).to.have.property('kid', 'feb-2020');
    });

    it('can be a nested JWT (implicit signing alg)', async function () {
      const resourceServer = {
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
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      const jwt = await token.save();

      const header = decode(jwt.split('.')[0]);
      expect(header).to.have.property('alg', 'ECDH-ES');
      expect(header).to.have.property('enc', 'A128GCM');
      expect(header).to.have.property('cty', 'at+jwt');
      expect(header).to.have.property('iss', this.provider.issuer);
      expect(header).to.have.property('aud', 'foo');
    });

    it('ensures "none" JWS algorithm cannot be used', async function () {
      const resourceServer = {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: {
            alg: 'none',
          },
        },
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('JWT Access Tokens may not use JWS algorithm "none"');
        return true;
      });
    });

    it('ensures HMAC JWS algorithms get a key', async function () {
      const resourceServer = {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: {
            alg: 'HS256',
          },
        },
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('missing jwt.sign.key Resource Server configuration');
        return true;
      });
    });

    it('ensures HMAC JWS algorithms get a secret key (1/2)', async function () {
      const resourceServer = {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: {
            alg: 'HS256',
            key: (await generateKeyPair('ec', { namedCurve: 'P-256' })).publicKey,
          },
        },
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('jwt.sign.key Resource Server configuration must be a secret (symmetric) key');
        return true;
      });
    });

    it('ensures HMAC JWS algorithms get a secret key (1/2)', async function () {
      const resourceServer = {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: {
            alg: 'HS256',
            key: (await generateKeyPair('ec', { namedCurve: 'P-256' })).privateKey,
          },
        },
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('jwt.sign.key Resource Server configuration must be a secret (symmetric) key');
        return true;
      });
    });

    it('ensures Asymmetric JWS algorithms have a key in the provider keystore', async function () {
      const resourceServer = {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          sign: {
            alg: 'ES384',
          },
        },
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('resolved Resource Server jwt configuration has no corresponding key in the provider\'s keystore');
        return true;
      });
    });

    it('ensures JWE key is public or secret', async function () {
      const resourceServer = {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          encrypt: {
            alg: 'dir',
            enc: 'A128GCM',
            key: (await generateKeyPair('ec', { namedCurve: 'P-256' })).privateKey,
          },
        },
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('jwt.encrypt.key Resource Server configuration must be a secret (symmetric) or a public key');
        return true;
      });
    });

    it('ensures Nested JWT when JWE encryption is a public one', async function () {
      const resourceServer = {
        accessTokenFormat: 'jwt',
        audience: 'foo',
        jwt: {
          encrypt: {
            alg: 'ECDH-ES',
            enc: 'A128GCM',
            key: (await generateKeyPair('ec', { namedCurve: 'P-256' })).publicKey,
          },
        },
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('missing jwt.sign Resource Server configuration');
        return true;
      });
    });

    // eslint-disable-next-line no-restricted-syntax
    for (const prop of ['alg', 'enc', 'key']) {
      // eslint-disable-next-line no-loop-func
      it(`ensures JWE Configuration has ${prop}`, async function () {
        const resourceServer = {
          accessTokenFormat: 'jwt',
          audience: 'foo',
          jwt: {
            encrypt: {
              alg: 'dir',
              enc: 'A128GCM',
              key: crypto.randomBytes(16),
            },
          },
        };

        delete resourceServer.jwt.encrypt[prop];

        const client = await this.provider.Client.find(clientId);
        const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
        return assert.rejects(token.save(), (err) => {
          expect(err).to.be.an('error');
          expect(err.message).to.equal(`missing jwt.encrypt.${prop} Resource Server configuration`);
          return true;
        });
      });
    }
  });

  it('for AccessToken', async function () {
    const upsert = sinon.spy(this.TestAdapter.for('AccessToken'), 'upsert');
    const client = await this.provider.Client.find(clientId);
    const token = new this.provider.AccessToken({ client, ...fullPayload });
    const issued = sinon.spy();
    this.provider.on('access_token.issued', issued);
    const jwt = await token.save();

    sinon.assert.notCalled(upsert);

    const { jti } = issued.getCall(0).args[0];
    const header = decode(jwt.split('.')[0]);
    expect(header).to.have.property('typ', 'at+jwt');
    const { iat, exp, ...payload } = decode(jwt.split('.')[1]);
    expect(iat).to.be.a('number');
    expect(exp).to.be.a('number');
    expect(payload).to.eql({
      ...extra,
      aud,
      client_id: clientId,
      iss: this.provider.issuer,
      jti,
      scope,
      sub: accountId,
      cnf: {
        'x5t#S256': s256,
        jkt: s256,
      },
    });
  });

  it('for pairwise AccessToken', async function () {
    const upsert = sinon.spy(this.TestAdapter.for('AccessToken'), 'upsert');
    const client = await this.provider.Client.find('pairwise');
    const token = new this.provider.AccessToken({ client, ...fullPayload });
    const issued = sinon.spy();
    this.provider.on('access_token.issued', issued);
    const jwt = await token.save();

    sinon.assert.notCalled(upsert);

    const { jti } = issued.getCall(0).args[0];
    const header = decode(jwt.split('.')[0]);
    expect(header).to.have.property('typ', 'at+jwt');
    const { iat, exp, ...payload } = decode(jwt.split('.')[1]);
    expect(iat).to.be.a('number');
    expect(exp).to.be.a('number');
    expect(payload).to.eql({
      ...extra,
      aud,
      client_id: 'pairwise',
      iss: this.provider.issuer,
      jti,
      scope,
      sub: 'pairwise-sub',
      cnf: {
        'x5t#S256': s256,
        jkt: s256,
      },
    });
  });

  it('for ClientCredentials', async function () {
    const upsert = sinon.spy(this.TestAdapter.for('ClientCredentials'), 'upsert');
    const client = await this.provider.Client.find(clientId);
    const token = new this.provider.ClientCredentials({ client, ...fullPayload });
    const issued = sinon.spy();
    this.provider.on('client_credentials.issued', issued);
    const jwt = await token.save();

    sinon.assert.notCalled(upsert);

    const { jti } = issued.getCall(0).args[0];
    const header = decode(jwt.split('.')[0]);
    expect(header).to.have.property('typ', 'at+jwt');
    const { iat, exp, ...payload } = decode(jwt.split('.')[1]);
    expect(iat).to.be.a('number');
    expect(exp).to.be.a('number');
    expect(payload).to.eql({
      ...extra,
      aud,
      client_id: clientId,
      sub: clientId,
      iss: this.provider.issuer,
      jti,
      scope,
      cnf: {
        'x5t#S256': s256,
        jkt: s256,
      },
    });
  });

  describe('customizers', () => {
    afterEach(function () {
      i(this.provider).configuration('formats.customizers').jwt = undefined;
    });

    it('allows the payload to be extended', async function () {
      const client = await this.provider.Client.find(clientId);
      const accessToken = new this.provider.AccessToken({ client, ...fullPayload });
      accessToken.resourceServer = resourceServer;
      i(this.provider).configuration('formats.customizers').jwt = (ctx, token, jwt) => {
        expect(token).to.equal(accessToken);
        expect(jwt).to.have.property('payload');
        expect(jwt).to.have.property('header', undefined);
        jwt.header = { customized: true, typ: 'foo' };
        jwt.payload.customized = true;
        jwt.payload.iss = 'foobar';
      };

      const jwt = await accessToken.save();
      const header = decode(jwt.split('.')[0]);
      expect(header).to.have.property('customized', true);
      expect(header).to.have.property('typ', 'foo');
      const payload = decode(jwt.split('.')[1]);
      expect(payload).to.have.property('customized', true);
      expect(payload).to.have.property('iss', 'foobar');
    });
  });
});
