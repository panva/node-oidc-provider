/* eslint-disable no-param-reassign */

const sinon = require('sinon').createSandbox();
const { expect } = require('chai');
const base64url = require('base64url');

const epochTime = require('../../lib/helpers/epoch_time');
const bootstrap = require('../test_helper');

const { formats: { AccessToken: FORMAT } } = global.TEST_CONFIGURATION_DEFAULTS;
const { spy, match: { string, number }, assert } = sinon;

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
        jti: upsert.getCall(0).args[0],
        jwt: string,
        kind,
        scope,
        sid,
        'x5t#S256': s256,
        jkt: s256,
        sessionUid,
        expiresWithSession,
        extra,
      });

      const { iat, jti, exp } = upsert.getCall(0).args[1];
      const header = decode(jwt.split('.')[0]);
      expect(header).to.have.property('typ', 'JWT');
      const payload = decode(jwt.split('.')[1]);
      expect(payload).to.eql({
        ...extra,
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
          jkt: s256,
        },
      });
    });

    it('for pairwise AccessToken', async function () {
      const kind = 'AccessToken';
      const upsert = spy(this.TestAdapter.for('AccessToken'), 'upsert');
      const client = await this.provider.Client.find('pairwise');
      const token = new this.provider.AccessToken({ client, ...fullPayload });
      const jwt = await token.save();

      assert.calledWith(upsert, string, {
        accountId,
        aud,
        claims,
        clientId: 'pairwise',
        exp: number,
        grantId,
        gty,
        iat: number,
        jti: upsert.getCall(0).args[0],
        jwt: string,
        kind,
        scope,
        sid,
        'x5t#S256': s256,
        jkt: s256,
        sessionUid,
        expiresWithSession,
        extra,
      });

      const { iat, jti, exp } = upsert.getCall(0).args[1];
      const header = decode(jwt.split('.')[0]);
      expect(header).to.have.property('typ', 'JWT');
      const payload = decode(jwt.split('.')[1]);
      expect(payload).to.eql({
        ...extra,
        aud,
        azp: 'pairwise',
        exp,
        iat,
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
      const kind = 'ClientCredentials';
      const upsert = spy(this.TestAdapter.for('ClientCredentials'), 'upsert');
      const token = new this.provider.ClientCredentials(fullPayload);
      const jwt = await token.save();

      assert.calledWith(upsert, string, {
        aud,
        clientId,
        exp: number,
        iat: number,
        jti: upsert.getCall(0).args[0],
        jwt: string,
        kind,
        scope,
        'x5t#S256': s256,
        jkt: s256,
        extra,
      });

      const { iat, jti, exp } = upsert.getCall(0).args[1];
      const header = decode(jwt.split('.')[0]);
      expect(header).to.have.property('typ', 'JWT');
      const payload = decode(jwt.split('.')[1]);
      expect(payload).to.eql({
        ...extra,
        aud,
        azp: clientId,
        exp,
        iat,
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
        const accessToken = new this.provider.AccessToken(fullPayload);
        i(this.provider).configuration('formats.customizers').jwt = (ctx, token, jwt) => {
          expect(token).to.equal(accessToken);
          expect(jwt).to.have.property('payload');
          expect(jwt).to.have.property('header', undefined);
          jwt.header = { customized: true };
          jwt.payload.customized = true;
        };

        const jwt = await accessToken.save();
        const header = decode(jwt.split('.')[0]);
        expect(header).to.have.property('customized', true);
        const payload = decode(jwt.split('.')[1]);
        expect(payload).to.have.property('customized', true);
      });
    });

    describe('invalid signing alg resolved', () => {
      ['none', 'HS256', 'HS384', 'HS512'].forEach((alg) => {
        it(`throws an Error when ${alg} is resolved`, async function () {
          i(this.provider).configuration('formats').jwtAccessTokenSigningAlg = async () => alg;
          const token = new this.provider.AccessToken(fullPayload);
          try {
            await token.save();
            throw new Error('expected to fail');
          } catch (err) {
            expect(err).to.be.an('error');
            expect(err.message).to.equal('JWT Access Tokens may not use JWA HMAC algorithms or "none"');
          }
        });
      });

      it('throws an Error when unsupported provider keystore alg is resolved', async function () {
        i(this.provider).configuration('formats').jwtAccessTokenSigningAlg = async () => 'ES384';
        const token = new this.provider.AccessToken(fullPayload);
        try {
          await token.save();
          throw new Error('expected to fail');
        } catch (err) {
          expect(err).to.be.an('error');
          expect(err.message).to.equal('invalid alg resolved for JWT Access Token signature, the alg must be an asymmetric one that the provider has in its keystore');
        }
      });
    });
  });
}
