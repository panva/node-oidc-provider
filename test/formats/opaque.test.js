const sinon = require('sinon').createSandbox();
const { expect } = require('chai');

const epochTime = require('../../lib/helpers/epoch_time');
const bootstrap = require('../test_helper');

const { formats: { AccessToken: FORMAT } } = global.TEST_CONFIGURATION_DEFAULTS;
const { spy, match: { string, number }, assert } = sinon;

if (FORMAT === 'opaque') {
  describe('opaque storage', () => {
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
    const aud = [clientId, 'foo'];
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

    // TODO: add Session and Interaction

    /* eslint-disable object-property-newline */
    const fullPayload = {
      accountId, claims, clientId, grantId, scope, sid, consumed, acr, amr, authTime, nonce,
      redirectUri, codeChallenge, codeChallengeMethod, aud, error, errorDescription, params,
      userCode, deviceInfo, gty, resource, policies, sessionUid, expiresWithSession,
      'x5t#S256': s256, inFlight, iiat, rotations, extra, jkt: s256,
    };
    /* eslint-enable object-property-newline */

    afterEach(sinon.restore);

    it('for AccessToken', async function () {
      const kind = 'AccessToken';
      const upsert = spy(this.TestAdapter.for('AccessToken'), 'upsert');
      const token = new this.provider.AccessToken(fullPayload);
      await token.save();

      expect(upsert.getCall(0).args[0]).to.have.lengthOf(43);
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
        kind,
        scope,
        sid,
        'x5t#S256': s256,
        jkt: s256,
        sessionUid,
        expiresWithSession,
        extra,
      });
    });

    it('for AuthorizationCode', async function () {
      const kind = 'AuthorizationCode';
      const upsert = spy(this.TestAdapter.for('AuthorizationCode'), 'upsert');
      const token = new this.provider.AuthorizationCode(fullPayload);
      await token.save();

      expect(upsert.getCall(0).args[0]).to.have.lengthOf(43);
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
        kind,
        nonce,
        redirectUri,
        resource,
        scope,
        sid,
        sessionUid,
        expiresWithSession,
      });
    });

    it('for DeviceCode', async function () {
      const kind = 'DeviceCode';
      const upsert = spy(this.TestAdapter.for('DeviceCode'), 'upsert');
      const token = new this.provider.DeviceCode(fullPayload);
      await token.save();

      expect(upsert.getCall(0).args[0]).to.have.lengthOf(43);
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
    });

    it('for RefreshToken', async function () {
      const kind = 'RefreshToken';
      const upsert = spy(this.TestAdapter.for('RefreshToken'), 'upsert');
      const token = new this.provider.RefreshToken(fullPayload);
      await token.save();

      expect(upsert.getCall(0).args[0]).to.have.lengthOf(43);
      assert.calledWith(upsert, string, {
        accountId,
        acr,
        amr,
        authTime,
        claims,
        iiat,
        rotations,
        clientId,
        consumed,
        exp: number,
        grantId,
        gty,
        iat: number,
        jti: upsert.getCall(0).args[0],
        kind,
        nonce,
        resource,
        scope,
        sid,
        'x5t#S256': s256,
        jkt: s256,
        sessionUid,
        expiresWithSession,
      });
    });

    it('for ClientCredentials', async function () {
      const kind = 'ClientCredentials';
      const upsert = spy(this.TestAdapter.for('ClientCredentials'), 'upsert');
      const token = new this.provider.ClientCredentials(fullPayload);
      await token.save();

      expect(upsert.getCall(0).args[0]).to.have.lengthOf(43);
      assert.calledWith(upsert, string, {
        aud,
        clientId,
        exp: number,
        iat: number,
        jti: upsert.getCall(0).args[0],
        kind,
        scope,
        'x5t#S256': s256,
        jkt: s256,
        extra,
      });
    });

    it('for InitialAccessToken', async function () {
      const kind = 'InitialAccessToken';
      const upsert = spy(this.TestAdapter.for('InitialAccessToken'), 'upsert');
      const token = new this.provider.InitialAccessToken({
        expiresIn: 100,
        ...fullPayload,
      });
      await token.save();

      expect(upsert.getCall(0).args[0]).to.have.lengthOf(43);
      assert.calledWith(upsert, string, {
        exp: number,
        iat: number,
        jti: upsert.getCall(0).args[0],
        kind,
        policies,
      });
    });

    it('for RegistrationAccessToken', async function () {
      const kind = 'RegistrationAccessToken';
      const upsert = spy(this.TestAdapter.for('RegistrationAccessToken'), 'upsert');
      const token = new this.provider.RegistrationAccessToken({
        expiresIn: 100,
        ...fullPayload,
      });
      await token.save();

      expect(upsert.getCall(0).args[0]).to.have.lengthOf(43);
      assert.calledWith(upsert, string, {
        clientId,
        kind,
        policies,
        jti: upsert.getCall(0).args[0],
        iat: number,
        exp: number,
      });
    });
  });
}
