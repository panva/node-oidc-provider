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

    /* eslint-disable object-property-newline */
    const fullPayload = {
      accountId, claims, clientId, grantId, scope, sid, consumed, acr, amr, authTime, nonce,
      redirectUri, codeChallenge, codeChallengeMethod, aud,
    };
    /* eslint-enable object-property-newline */

    afterEach(function () {
      [
        'AuthorizationCode', 'AccessToken', 'RefreshToken', 'ClientCredentials', 'InitialAccessToken', 'RegistrationAccessToken',
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
        grantId,
        accountId,
        claims,
        clientId,
        aud,
        scope,
        sid,
        kind,
        iss: this.provider.issuer,
        jti: upsert.getCall(0).args[0],
        iat: number,
        exp: number,
      });
    });

    it('for AuthorizationCode', async function () {
      const kind = 'AuthorizationCode';
      const upsert = spy(this.TestAdapter.for('AuthorizationCode'), 'upsert');
      const token = new this.provider.AuthorizationCode(fullPayload);
      await token.save();

      assert.calledWith(upsert, string, {
        grantId,
        consumed,
        acr,
        codeChallenge,
        codeChallengeMethod,
        amr,
        authTime,
        accountId,
        claims,
        clientId,
        scope,
        nonce,
        redirectUri,
        sid,
        kind,
        iss: this.provider.issuer,
        jti: upsert.getCall(0).args[0],
        iat: number,
        exp: number,
      });
    });

    it('for RefreshToken', async function () {
      const kind = 'RefreshToken';
      const upsert = spy(this.TestAdapter.for('RefreshToken'), 'upsert');
      const token = new this.provider.RefreshToken(fullPayload);
      await token.save();

      assert.calledWith(upsert, string, {
        grantId,
        consumed,
        accountId,
        acr,
        amr,
        authTime,
        claims,
        clientId,
        nonce,
        scope,
        sid,
        kind,
        iss: this.provider.issuer,
        jti: upsert.getCall(0).args[0],
        iat: number,
        exp: number,
      });
    });

    it('for ClientCredentials', async function () {
      const kind = 'ClientCredentials';
      const upsert = spy(this.TestAdapter.for('ClientCredentials'), 'upsert');
      const token = new this.provider.ClientCredentials(fullPayload);
      await token.save();

      assert.calledWith(upsert, string, {
        clientId,
        scope,
        aud,
        kind,
        iss: this.provider.issuer,
        jti: upsert.getCall(0).args[0],
        iat: number,
        exp: number,
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
        kind,
        iss: this.provider.issuer,
        jti: upsert.getCall(0).args[0],
        iat: number,
        exp: number,
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
