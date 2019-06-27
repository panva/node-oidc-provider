const { spy, match: { string, number }, assert } = require('sinon');
const { expect } = require('chai');
const base64url = require('base64url');

const { formats: { default: FORMAT } } = require('../../lib/helpers/defaults');
const epochTime = require('../../lib/helpers/epoch_time');
const bootstrap = require('../test_helper');

function decode(paseto) {
  return JSON.parse(base64url.toBuffer(paseto.split('.')[2]).slice(0, -64));
}

if (FORMAT === 'paseto') {
  describe('paseto storage', () => {
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
    const { kid } = global.keystore.get({ kty: 'OKP' });

    // TODO: add Session and Interaction

    /* eslint-disable object-property-newline */
    const fullPayload = {
      accountId, claims, clientId, grantId, scope, sid, consumed, acr, amr, authTime, nonce,
      redirectUri, codeChallenge, codeChallengeMethod, aud, error, errorDescription, params,
      userCode, deviceInfo, gty, resource, policies, sessionUid, expiresWithSession,
      'x5t#S256': s256, inFlight, iiat, rotations, extra,
    };
    /* eslint-enable object-property-newline */

    afterEach(function () {
      [
        'AuthorizationCode', 'AccessToken', 'RefreshToken', 'ClientCredentials', 'InitialAccessToken', 'RegistrationAccessToken', 'DeviceCode',
      ].forEach((model) => {
        if (this.TestAdapter.for(model).upsert.restore) {
          this.TestAdapter.for(model).upsert.restore();
        }
      });
    });

    it('for AccessToken', async function () {
      const kind = 'AccessToken';
      const upsert = spy(this.TestAdapter.for('AccessToken'), 'upsert');
      const token = new this.provider.AccessToken(fullPayload);
      const paseto = await token.save();

      assert.calledWith(upsert, string, {
        accountId,
        aud,
        claims,
        clientId,
        exp: number,
        grantId,
        gty,
        iat: number,
        jti: upsert.getCall(0).args[0],
        paseto: string,
        kind,
        scope,
        sid,
        'x5t#S256': s256,
        sessionUid,
        expiresWithSession,
        extra,
      });

      const { iat, jti, exp } = upsert.getCall(0).args[1];
      const payload = decode(paseto);
      expect(payload).to.eql({
        ...extra,
        aud,
        azp: clientId,
        kid,
        exp: new Date(exp * 1000).toISOString(),
        iat: new Date(iat * 1000).toISOString(),
        iss: this.provider.issuer,
        jti,
        scope,
        sub: accountId,
        cnf: {
          'x5t#S256': s256,
        },
      });
    });

    it('for AuthorizationCode', async function () {
      const kind = 'AuthorizationCode';
      const upsert = spy(this.TestAdapter.for('AuthorizationCode'), 'upsert');
      const token = new this.provider.AuthorizationCode(fullPayload);
      const paseto = await token.save();

      assert.calledWith(upsert, string, {
        accountId,
        acr,
        amr,
        authTime,
        claims,
        clientId,
        codeChallenge,
        codeChallengeMethod,
        consumed,
        exp: number,
        grantId,
        iat: number,
        jti: upsert.getCall(0).args[0],
        paseto: string,
        kind,
        nonce,
        redirectUri,
        resource,
        scope,
        sid,
        sessionUid,
        expiresWithSession,
      });

      const { iat, jti, exp } = upsert.getCall(0).args[1];
      const payload = decode(paseto);
      expect(payload).to.eql({
        aud: clientId,
        kid,
        exp: new Date(exp * 1000).toISOString(),
        iat: new Date(iat * 1000).toISOString(),
        iss: this.provider.issuer,
        jti,
        scope,
        sub: accountId,
      });
    });

    it('for RefreshToken', async function () {
      const kind = 'RefreshToken';
      const upsert = spy(this.TestAdapter.for('RefreshToken'), 'upsert');
      const token = new this.provider.RefreshToken(fullPayload);
      const paseto = await token.save();

      assert.calledWith(upsert, string, {
        accountId,
        acr,
        iiat,
        rotations,
        amr,
        authTime,
        claims,
        clientId,
        consumed,
        exp: number,
        grantId,
        gty,
        iat: number,
        jti: upsert.getCall(0).args[0],
        paseto: string,
        kind,
        nonce,
        resource,
        scope,
        sid,
        'x5t#S256': s256,
        sessionUid,
        expiresWithSession,
      });

      const { iat, jti, exp } = upsert.getCall(0).args[1];
      const payload = decode(paseto);
      expect(payload).to.eql({
        aud: clientId,
        kid,
        exp: new Date(exp * 1000).toISOString(),
        iat: new Date(iat * 1000).toISOString(),
        iss: this.provider.issuer,
        jti,
        scope,
        sub: accountId,
        cnf: {
          'x5t#S256': s256,
        },
      });
    });

    it('for DeviceCode', async function () {
      const kind = 'DeviceCode';
      const upsert = spy(this.TestAdapter.for('DeviceCode'), 'upsert');
      const token = new this.provider.DeviceCode(fullPayload);
      const paseto = await token.save();

      assert.calledWith(upsert, string, {
        accountId,
        acr,
        amr,
        authTime,
        claims,
        clientId,
        codeChallenge,
        codeChallengeMethod,
        consumed,
        deviceInfo,
        error,
        errorDescription,
        exp: number,
        grantId,
        gty,
        iat: number,
        jti: upsert.getCall(0).args[0],
        paseto,
        kind,
        nonce,
        params,
        resource,
        scope,
        sid,
        userCode,
        sessionUid,
        expiresWithSession,
        inFlight,
      });

      const { iat, jti, exp } = upsert.getCall(0).args[1];
      const payload = decode(paseto);
      expect(payload).to.eql({
        aud: clientId,
        kid,
        exp: new Date(exp * 1000).toISOString(),
        iat: new Date(iat * 1000).toISOString(),
        iss: this.provider.issuer,
        jti,
        scope,
        sub: accountId,
      });
    });

    it('for ClientCredentials', async function () {
      const kind = 'ClientCredentials';
      const upsert = spy(this.TestAdapter.for('ClientCredentials'), 'upsert');
      const token = new this.provider.ClientCredentials(fullPayload);
      const paseto = await token.save();

      assert.calledWith(upsert, string, {
        aud,
        clientId,
        exp: number,
        iat: number,
        jti: upsert.getCall(0).args[0],
        paseto: string,
        kind,
        scope,
        'x5t#S256': s256,
        extra,
      });

      const { iat, jti, exp } = upsert.getCall(0).args[1];
      const payload = decode(paseto);
      expect(payload).to.eql({
        ...extra,
        aud,
        azp: clientId,
        kid,
        exp: new Date(exp * 1000).toISOString(),
        iat: new Date(iat * 1000).toISOString(),
        iss: this.provider.issuer,
        jti,
        scope,
        cnf: {
          'x5t#S256': s256,
        },
      });
    });

    it('for InitialAccessToken', async function () {
      const kind = 'InitialAccessToken';
      const upsert = spy(this.TestAdapter.for('InitialAccessToken'), 'upsert');
      const token = new this.provider.InitialAccessToken({
        expiresIn: 100,
        ...fullPayload,
      });
      const paseto = await token.save();

      assert.calledWith(upsert, string, {
        exp: number,
        iat: number,
        jti: upsert.getCall(0).args[0],
        paseto: string,
        kind,
        policies,
      });

      const { iat, jti, exp } = upsert.getCall(0).args[1];
      const payload = decode(paseto);
      expect(payload).to.eql({
        kid,
        exp: new Date(exp * 1000).toISOString(),
        iat: new Date(iat * 1000).toISOString(),
        iss: this.provider.issuer,
        jti,
      });
    });

    it('for RegistrationAccessToken', async function () {
      const kind = 'RegistrationAccessToken';
      const upsert = spy(this.TestAdapter.for('RegistrationAccessToken'), 'upsert');
      const token = new this.provider.RegistrationAccessToken({
        expiresIn: 100,
        ...fullPayload,
      });
      const paseto = await token.save();

      assert.calledWith(upsert, string, {
        clientId,
        policies,
        exp: number,
        iat: number,
        jti: upsert.getCall(0).args[0],
        paseto: string,
        kind,
      });

      const { iat, jti, exp } = upsert.getCall(0).args[1];
      const payload = decode(paseto);
      expect(payload).to.eql({
        aud: clientId,
        kid,
        exp: new Date(exp * 1000).toISOString(),
        iat: new Date(iat * 1000).toISOString(),
        iss: this.provider.issuer,
        jti,
      });
    });

    describe('paseto when keys are missing', () => {
      before(bootstrap(__dirname, { config: 'noed25519' }));

      it('throws an Error', async function () {
        const token = new this.provider.AccessToken(fullPayload);
        try {
          await token.save();
          throw new Error('expected to fail');
        } catch (err) {
          expect(err).to.be.an('error');
          expect(err.message).to.equal('No Ed25519 signing key found to sign the PASETO formatted token with');
        }
      });
    });
  });
}
