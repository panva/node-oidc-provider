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
    const aud = ['foo', 'bar'];
    const gty = 'foo';
    const error = 'access_denied';
    const errorDescription = 'resource owner denied access';
    const params = { foo: 'bar' };
    const userCode = '1384-3217';
    const deviceInfo = { foo: 'bar' };
    const s256 = '_gPMqAT8BELhXwBa2nIT0OvdWtQCiF_g09nAyHhgCe0';
    const resource = 'urn:foo:bar';
    const policies = ['foo'];

    /* eslint-disable object-property-newline */
    const fullPayload = {
      accountId, claims, clientId, grantId, scope, sid, consumed, acr, amr, authTime, nonce,
      redirectUri, codeChallenge, codeChallengeMethod, aud, error, errorDescription, params,
      userCode, deviceInfo, gty, resource, policies,
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
      const jwt = await token.save();

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
        jwt: string,
        kind,
        scope,
        sid,
        'x5t#S256': s256,
      });

      const { iat, jti, exp } = upsert.getCall(0).args[1];
      const payload = decode(jwt.split('.')[1]);
      expect(payload).to.eql({
        aud,
        azp: clientId,
        exp,
        iat,
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
      const jwt = await token.save();

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
        jwt: string,
        kind,
        nonce,
        redirectUri,
        resource,
        scope,
        sid,
      });

      const { iat, jti, exp } = upsert.getCall(0).args[1];
      const payload = decode(jwt.split('.')[1]);
      expect(payload).to.eql({
        aud: clientId,
        exp,
        iat,
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
      const jwt = await token.save();

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
        jwt: string,
        kind,
        nonce,
        resource,
        scope,
        sid,
      });

      const { iat, jti, exp } = upsert.getCall(0).args[1];
      const payload = decode(jwt.split('.')[1]);
      expect(payload).to.eql({
        aud: clientId,
        exp,
        iat,
        iss: this.provider.issuer,
        jti,
        scope,
        sub: accountId,
      });
    });

    it('for DeviceCode', async function () {
      const kind = 'DeviceCode';
      const upsert = spy(this.TestAdapter.for('DeviceCode'), 'upsert');
      const token = new this.provider.DeviceCode(fullPayload);
      const jwt = await token.save();

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
        jwt,
        kind,
        nonce,
        params,
        resource,
        scope,
        sid,
        userCode,
      });

      const { iat, jti, exp } = upsert.getCall(0).args[1];
      const payload = decode(jwt.split('.')[1]);
      expect(payload).to.eql({
        aud: clientId,
        exp,
        iat,
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
      const jwt = await token.save();

      assert.calledWith(upsert, string, {
        aud,
        clientId,
        exp: number,
        iat: number,
        iss: this.provider.issuer,
        jti: upsert.getCall(0).args[0],
        jwt: string,
        kind,
        scope,
        'x5t#S256': s256,
      });

      const { iat, jti, exp } = upsert.getCall(0).args[1];
      const payload = decode(jwt.split('.')[1]);
      expect(payload).to.eql({
        aud,
        azp: clientId,
        exp,
        iat,
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
      const jwt = await token.save();

      assert.calledWith(upsert, string, {
        exp: number,
        iat: number,
        iss: this.provider.issuer,
        jti: upsert.getCall(0).args[0],
        jwt: string,
        kind,
        policies,
      });

      const { iat, jti, exp } = upsert.getCall(0).args[1];
      const payload = decode(jwt.split('.')[1]);
      expect(payload).to.eql({
        exp,
        iat,
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
      const jwt = await token.save();

      assert.calledWith(upsert, string, {
        clientId,
        policies,
        exp: number,
        iat: number,
        iss: this.provider.issuer,
        jti: upsert.getCall(0).args[0],
        jwt: string,
        kind,
      });

      const { iat, jti, exp } = upsert.getCall(0).args[1];
      const payload = decode(jwt.split('.')[1]);
      expect(payload).to.eql({
        aud: clientId,
        exp,
        iat,
        iss: this.provider.issuer,
        jti,
      });
    });
  });
}
