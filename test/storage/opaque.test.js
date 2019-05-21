const { spy, match: { string, number }, assert } = require('sinon');

const { formats: { default: FORMAT } } = require('../../lib/helpers/defaults');
const epochTime = require('../../lib/helpers/epoch_time');
const bootstrap = require('../test_helper');

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
    const s256 = '_gPMqAT8BELhXwBa2nIT0OvdWtQCiF_g09nAyHhgCe0';

    /* eslint-disable object-property-newline */
    const fullPayload = {
      accountId, claims, clientId, grantId, scope, sid, consumed, acr, amr, authTime, nonce,
      redirectUri, codeChallenge, codeChallengeMethod, aud, error, errorDescription, params,
      userCode, deviceInfo, gty,
      'x5t#S256': s256,
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
      await token.save();

      assert.calledWith(upsert, string, {
        accountId,
        aud,
        claims,
        clientId,
        exp: number,
        grantId,
        gty,
        iat: number,
        iss: this.provider.issuer,
        jti: upsert.getCall(0).args[0],
        kind,
        scope,
        sid,
        'x5t#S256': s256,
      });
    });

    it('for AuthorizationCode', async function () {
      const kind = 'AuthorizationCode';
      const upsert = spy(this.TestAdapter.for('AuthorizationCode'), 'upsert');
      const token = new this.provider.AuthorizationCode(fullPayload);
      await token.save();

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
        iss: this.provider.issuer,
        jti: upsert.getCall(0).args[0],
        kind,
        nonce,
        redirectUri,
        scope,
        sid,
      });
    });

    it('for DeviceCode', async function () {
      const kind = 'DeviceCode';
      const upsert = spy(this.TestAdapter.for('DeviceCode'), 'upsert');
      const token = new this.provider.DeviceCode(fullPayload);
      await token.save();

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
        iss: this.provider.issuer,
        jti: upsert.getCall(0).args[0],
        kind,
        nonce,
        params,
        scope,
        sid,
        userCode,
      });
    });

    it('for RefreshToken', async function () {
      const kind = 'RefreshToken';
      const upsert = spy(this.TestAdapter.for('RefreshToken'), 'upsert');
      const token = new this.provider.RefreshToken(fullPayload);
      await token.save();

      assert.calledWith(upsert, string, {
        accountId,
        acr,
        amr,
        authTime,
        claims,
        clientId,
        consumed,
        exp: number,
        grantId,
        gty,
        iat: number,
        iss: this.provider.issuer,
        jti: upsert.getCall(0).args[0],
        kind,
        nonce,
        scope,
        sid,
      });
    });

    it('for ClientCredentials', async function () {
      const kind = 'ClientCredentials';
      const upsert = spy(this.TestAdapter.for('ClientCredentials'), 'upsert');
      const token = new this.provider.ClientCredentials(fullPayload);
      await token.save();

      assert.calledWith(upsert, string, {
        aud,
        clientId,
        exp: number,
        iat: number,
        iss: this.provider.issuer,
        jti: upsert.getCall(0).args[0],
        kind,
        scope,
        'x5t#S256': s256,
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

      assert.calledWith(upsert, string, {
        exp: number,
        iat: number,
        iss: this.provider.issuer,
        jti: upsert.getCall(0).args[0],
        kind,
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

      assert.calledWith(upsert, string, {
        clientId,
        kind,
        iss: this.provider.issuer,
        jti: upsert.getCall(0).args[0],
        iat: number,
        exp: number,
      });
    });
  });
}
