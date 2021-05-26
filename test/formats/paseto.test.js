/* eslint-disable no-shadow */
/* eslint-disable no-param-reassign */
const { strict: assert } = require('assert');
const crypto = require('crypto');
const util = require('util');

const sinon = require('sinon').createSandbox();
const { expect } = require('chai');
const paseto = require('paseto');

const epochTime = require('../../lib/helpers/epoch_time');
const bootstrap = require('../test_helper');

const generateKeyPair = util.promisify(crypto.generateKeyPair);

describe('paseto format', () => {
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
    accessTokenFormat: 'paseto',
    audience: 'foo',
    paseto: {
      version: 1,
      purpose: 'public',
    },
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
    it('v1.public', async function () {
      const resourceServer = {
        accessTokenFormat: 'paseto',
        audience: 'foo',
        paseto: {
          version: 1,
          purpose: 'public',
        },
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      expect(await token.save()).to.match(/^v1\.public\./);
    });

    it('v2.public', async function () {
      const resourceServer = {
        accessTokenFormat: 'paseto',
        audience: 'foo',
        paseto: {
          version: 2,
          purpose: 'public',
        },
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      expect(await token.save()).to.match(/^v2\.public\./);
    });

    it('v1.local', async function () {
      const resourceServer = {
        accessTokenFormat: 'paseto',
        audience: 'foo',
        paseto: {
          version: 1,
          purpose: 'local',
          key: crypto.randomBytes(32),
        },
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      expect(await token.save()).to.match(/^v1\.local\./);
    });

    it('v1.local (keyObject)', async function () {
      const resourceServer = {
        accessTokenFormat: 'paseto',
        audience: 'foo',
        paseto: {
          version: 1,
          purpose: 'local',
          key: crypto.createSecretKey(crypto.randomBytes(32)),
        },
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      expect(await token.save()).to.match(/^v1\.local\./);
    });

    it('v2.local is not supported', async function () {
      const resourceServer = {
        accessTokenFormat: 'paseto',
        audience: 'foo',
        paseto: {
          version: 2,
          purpose: 'local',
          key: crypto.randomBytes(32),
        },
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('unsupported PASETO version and purpose');
        return true;
      });
    });

    it('public kid selection failing', async function () {
      const resourceServer = {
        accessTokenFormat: 'paseto',
        audience: 'foo',
        paseto: {
          kid: 'foobar',
          version: 1,
          purpose: 'public',
        },
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('resolved Resource Server paseto configuration has no corresponding key in the provider\'s keystore');
        return true;
      });
    });

    it('kid must be a string', async function () {
      const resourceServer = {
        accessTokenFormat: 'paseto',
        audience: 'foo',
        paseto: {
          kid: 200,
          version: 1,
          purpose: 'local',
          key: crypto.randomBytes(32),
        },
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('paseto.kid must be a string when provided');
        return true;
      });
    });

    it('unsupported PASETO version and purpose', async function () {
      const resourceServer = {
        accessTokenFormat: 'paseto',
        audience: 'foo',
        paseto: {
          version: 1,
          purpose: 'foobar',
        },
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('unsupported PASETO version and purpose');
        return true;
      });
    });

    it('unsupported "paseto.version"', async function () {
      const resourceServer = {
        accessTokenFormat: 'paseto',
        audience: 'foo',
        paseto: {
          version: 3,
          purpose: 'foobar',
        },
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('unsupported "paseto.version"');
        return true;
      });
    });

    it('local paseto requires a key', async function () {
      const resourceServer = {
        accessTokenFormat: 'paseto',
        audience: 'foo',
        paseto: {
          version: 1,
          purpose: 'local',
        },
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('local purpose PASETO Resource Server requires a "paseto.key"');
        return true;
      });
    });

    it('local paseto requires a key 32 bytes', async function () {
      const resourceServer = {
        accessTokenFormat: 'paseto',
        audience: 'foo',
        paseto: {
          version: 1,
          purpose: 'local',
          key: crypto.randomBytes(16),
        },
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('local purpose PASETO Resource Server "paseto.key" must be 256 bits long secret key');
        return true;
      });
    });

    it('local paseto requires a secret key (private provided)', async function () {
      const resourceServer = {
        accessTokenFormat: 'paseto',
        audience: 'foo',
        paseto: {
          version: 1,
          purpose: 'local',
          key: await (await generateKeyPair('ed25519')).privateKey,
        },
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('local purpose PASETO Resource Server "paseto.key" must be 256 bits long secret key');
        return true;
      });
    });

    it('local paseto requires a secret key (public provided)', async function () {
      const resourceServer = {
        accessTokenFormat: 'paseto',
        audience: 'foo',
        paseto: {
          version: 1,
          purpose: 'local',
          key: await (await generateKeyPair('ed25519')).publicKey,
        },
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('local purpose PASETO Resource Server "paseto.key" must be 256 bits long secret key');
        return true;
      });
    });

    it('missing paseto configuration', async function () {
      const resourceServer = {
        accessTokenFormat: 'paseto',
        audience: 'foo',
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('missing "paseto" Resource Server configuration');
        return true;
      });
    });

    it('invalid paseto configuration type', async function () {
      const resourceServer = {
        accessTokenFormat: 'paseto',
        audience: 'foo',
        paseto: null,
      };

      const client = await this.provider.Client.find(clientId);
      const token = new this.provider.AccessToken({ client, ...fullPayload, resourceServer });
      return assert.rejects(token.save(), (err) => {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('missing "paseto" Resource Server configuration');
        return true;
      });
    });
  });

  it('for AccessToken', async function () {
    const upsert = sinon.spy(this.TestAdapter.for('AccessToken'), 'upsert');
    const client = await this.provider.Client.find(clientId);
    const token = new this.provider.AccessToken({ client, ...fullPayload });
    const issued = sinon.spy();
    this.provider.on('access_token.issued', issued);
    const p = await token.save();

    sinon.assert.notCalled(upsert);

    const { jti } = issued.getCall(0).args[0];
    const { payload: { iat, exp, ...payload } } = paseto.decode(p);
    expect(iat).to.be.a('string');
    expect(exp).to.be.a('string');
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
    const p = await token.save();

    sinon.assert.notCalled(upsert);

    const { jti } = issued.getCall(0).args[0];
    const { payload: { iat, exp, ...payload } } = paseto.decode(p);
    expect(iat).to.be.a('string');
    expect(exp).to.be.a('string');
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
    const p = await token.save();

    sinon.assert.notCalled(upsert);

    const { jti } = issued.getCall(0).args[0];
    const { payload: { iat, exp, ...payload } } = paseto.decode(p);
    expect(iat).to.be.a('string');
    expect(exp).to.be.a('string');
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
      i(this.provider).configuration('formats.customizers').paseto = undefined;
    });

    it('allows the payload to be extended', async function () {
      const client = await this.provider.Client.find(clientId);
      const accessToken = new this.provider.AccessToken({ client, ...fullPayload });
      accessToken.resourceServer = resourceServer;
      i(this.provider).configuration('formats.customizers').paseto = (ctx, token, paseto) => {
        expect(token).to.equal(accessToken);
        expect(paseto).to.have.property('payload');
        expect(paseto).to.have.property('footer', undefined);
        paseto.footer = { customized: true };
        paseto.payload.customized = true;
        paseto.payload.iss = 'foobar';
      };

      const token = await accessToken.save();
      const { footer, payload } = paseto.decode(token);
      expect(JSON.parse(footer)).to.have.property('customized', true);
      expect(payload).to.have.property('customized', true);
      expect(payload).to.have.property('iss', 'foobar');
    });
  });
});
