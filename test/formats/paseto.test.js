/* eslint-disable no-param-reassign */

const { createPublicKey } = require('crypto');

const sinon = require('sinon').createSandbox();
const { expect } = require('chai');

const epochTime = require('../../lib/helpers/epoch_time');
const bootstrap = require('../test_helper');

const { formats: { AccessToken: FORMAT } } = global.TEST_CONFIGURATION_DEFAULTS;
const { spy, match: { string, number }, assert } = sinon;

if (FORMAT === 'paseto') {
  const pasetoLib = require('paseto'); // eslint-disable-line global-require
  const key = createPublicKey(global.keystore.get({ kty: 'OKP' }).toPEM(false));
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
      'x5t#S256': s256, inFlight, iiat, rotations, extra, jkt: s256,
    };
    /* eslint-enable object-property-newline */

    afterEach(sinon.restore);

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
        jkt: s256,
        sessionUid,
        expiresWithSession,
        extra,
      });

      const { iat, jti, exp } = upsert.getCall(0).args[1];
      const payload = await pasetoLib.V2.verify(paseto, key);
      expect(payload).to.eql({
        ...extra,
        aud,
        client_id: clientId,
        kid,
        exp: new Date(exp * 1000).toISOString(),
        iat: new Date(iat * 1000).toISOString(),
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
      const paseto = await token.save();

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
        paseto: string,
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
      const payload = await pasetoLib.V2.verify(paseto, key);
      expect(payload).to.eql({
        ...extra,
        aud,
        client_id: 'pairwise',
        kid,
        exp: new Date(exp * 1000).toISOString(),
        iat: new Date(iat * 1000).toISOString(),
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
        jkt: s256,
        extra,
      });

      const { iat, jti, exp } = upsert.getCall(0).args[1];
      const payload = await pasetoLib.V2.verify(paseto, key);
      expect(payload).to.eql({
        ...extra,
        aud,
        client_id: clientId,
        kid,
        exp: new Date(exp * 1000).toISOString(),
        iat: new Date(iat * 1000).toISOString(),
        iss: this.provider.issuer,
        jti,
        sub: clientId,
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
        const accessToken = new this.provider.AccessToken(fullPayload);
        i(this.provider).configuration('formats.customizers').paseto = (ctx, token, paseto) => {
          expect(token).to.equal(accessToken);
          expect(paseto).to.have.property('payload');
          paseto.payload.customized = true;
        };

        let paseto = await accessToken.save();
        const { payload } = await pasetoLib.V2.verify(paseto, key, { complete: true });
        expect(payload).to.have.property('customized', true);

        i(this.provider).configuration('formats.customizers').paseto = (ctx, token, t) => {
          expect(t).to.have.property('footer', undefined);
          t.footer = { customized: true };
        };

        paseto = await accessToken.save();
        let { footer } = await pasetoLib.V2.verify(paseto, key, { complete: true });
        expect(footer).to.be.instanceOf(Buffer);
        expect(JSON.parse(footer)).to.have.property('customized', true);

        i(this.provider).configuration('formats.customizers').paseto = (ctx, token, t) => {
          t.footer = Buffer.from('foobar');
        };

        paseto = await accessToken.save();
        ({ footer } = await pasetoLib.V2.verify(paseto, key, { complete: true }));
        expect(footer).to.be.instanceOf(Buffer);
        expect(footer.toString()).to.eql('foobar');

        i(this.provider).configuration('formats.customizers').paseto = (ctx, token, t) => {
          t.footer = 'foobarbaz';
        };

        paseto = await accessToken.save();
        ({ footer } = await pasetoLib.V2.verify(paseto, key, { complete: true }));
        expect(footer).to.be.instanceOf(Buffer);
        expect(footer.toString()).to.eql('foobarbaz');
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
