const { spy, match: { string, number }, assert } = require('sinon');
const { expect } = require('chai');
const base64url = require('base64url');

const { formats: { default: FORMAT } } = require('../../lib/helpers/defaults');
const epochTime = require('../../lib/helpers/epoch_time');
const bootstrap = require('../test_helper');

function decode(b64urljson) {
  return JSON.parse(base64url.decode(b64urljson));
}

if (FORMAT === 'jwt') {
  describe('jwt storage', () => {
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
      const jwt = await token.save();

      assert.calledWith(upsert, string, {
        jwt: string,
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

      const { iat, jti, exp } = upsert.getCall(0).args[1];
      const payload = decode(jwt.split('.')[1]);
      expect(payload).to.eql({
        iat,
        jti,
        exp,
        sub: accountId,
        azp: clientId,
        aud,
        scope,
        iss: this.provider.issuer,
      });
    });

    it('for AuthorizationCode', async function () {
      const kind = 'AuthorizationCode';
      const upsert = spy(this.TestAdapter.for('AuthorizationCode'), 'upsert');
      const token = new this.provider.AuthorizationCode(fullPayload);
      const jwt = await token.save();

      assert.calledWith(upsert, string, {
        jwt: string,
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

      const { iat, jti, exp } = upsert.getCall(0).args[1];
      const payload = decode(jwt.split('.')[1]);
      expect(payload).to.eql({
        iat,
        jti,
        exp,
        sub: accountId,
        aud: clientId,
        scope,
        iss: this.provider.issuer,
      });
    });

    it('for RefreshToken', async function () {
      const kind = 'RefreshToken';
      const upsert = spy(this.TestAdapter.for('RefreshToken'), 'upsert');
      const token = new this.provider.RefreshToken(fullPayload);
      const jwt = await token.save();

      assert.calledWith(upsert, string, {
        jwt: string,
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

      const { iat, jti, exp } = upsert.getCall(0).args[1];
      const payload = decode(jwt.split('.')[1]);
      expect(payload).to.eql({
        iat,
        jti,
        exp,
        sub: accountId,
        aud: clientId,
        scope,
        iss: this.provider.issuer,
      });
    });

    it('for ClientCredentials', async function () {
      const kind = 'ClientCredentials';
      const upsert = spy(this.TestAdapter.for('ClientCredentials'), 'upsert');
      const token = new this.provider.ClientCredentials(fullPayload);
      const jwt = await token.save();

      assert.calledWith(upsert, string, {
        jwt: string,
        clientId,
        scope,
        aud,
        kind,
        iss: this.provider.issuer,
        jti: upsert.getCall(0).args[0],
        iat: number,
        exp: number,
      });

      const { iat, jti, exp } = upsert.getCall(0).args[1];
      const payload = decode(jwt.split('.')[1]);
      expect(payload).to.eql({
        iat,
        jti,
        exp,
        azp: clientId,
        aud,
        scope,
        iss: this.provider.issuer,
      });
    });

    it('for InitialAccessToken', async function () {
      const kind = 'InitialAccessToken';
      const upsert = spy(this.TestAdapter.for('InitialAccessToken'), 'upsert');
      const token = new this.provider.InitialAccessToken({
        expiresIn: 100,
        ...fullPayload,
      });
      const jwt = await token.save();

      assert.calledWith(upsert, string, {
        jwt: string,
        kind,
        iss: this.provider.issuer,
        jti: upsert.getCall(0).args[0],
        iat: number,
        exp: number,
      });

      const { iat, jti, exp } = upsert.getCall(0).args[1];
      const payload = decode(jwt.split('.')[1]);
      expect(payload).to.eql({
        iat,
        jti,
        exp,
        iss: this.provider.issuer,
      });
    });

    it('for RegistrationAccessToken', async function () {
      const kind = 'RegistrationAccessToken';
      const upsert = spy(this.TestAdapter.for('RegistrationAccessToken'), 'upsert');
      const token = new this.provider.RegistrationAccessToken({
        expiresIn: 100,
        ...fullPayload,
      });
      const jwt = await token.save();

      assert.calledWith(upsert, string, {
        jwt: string,
        clientId,
        kind,
        iss: this.provider.issuer,
        jti: upsert.getCall(0).args[0],
        iat: number,
        exp: number,
      });

      const { iat, jti, exp } = upsert.getCall(0).args[1];
      const payload = decode(jwt.split('.')[1]);
      expect(payload).to.eql({
        iat,
        jti,
        exp,
        aud: clientId,
        iss: this.provider.issuer,
      });
    });
  });
}
