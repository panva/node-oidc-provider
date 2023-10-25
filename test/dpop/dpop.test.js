import * as url from 'node:url';
import { createHash, randomBytes, randomUUID } from 'node:crypto';

import sinon from 'sinon';
import { expect } from 'chai';
import {
  SignJWT, exportJWK, calculateJwkThumbprint, generateKeyPair,
} from 'jose';

import nanoid from '../../lib/helpers/nanoid.js';
import epochTime from '../../lib/helpers/epoch_time.js';
import bootstrap, { skipConsent } from '../test_helper.js';
import * as base64url from '../../lib/helpers/base64url.js';

function ath(accessToken) {
  return base64url.encode(createHash('sha256').update(accessToken).digest());
}

function DPoP(keypair, htu, htm, nonce = undefined, accessToken = undefined) {
  return new SignJWT({
    htu,
    htm,
    nonce,
    ath: accessToken ? ath(accessToken) : undefined,
  }).setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: keypair.publicKey.export({ format: 'jwk' }) })
    .setJti(nanoid())
    .setIssuedAt()
    .sign(keypair.privateKey);
}

describe('features.dPoP', () => {
  before(bootstrap(import.meta.url));
  before(function () { return this.login({ scope: 'openid offline_access' }); });
  skipConsent();
  before(async function () {
    this.keypair = await generateKeyPair('ES256');
    this.jwk = await exportJWK(this.keypair.publicKey);
    this.thumbprint = await calculateJwkThumbprint(this.jwk);
  });

  it('extends discovery', function () {
    return this.agent.get('/.well-known/openid-configuration')
      .expect(200)
      .expect((response) => {
        expect(response.body).to.have.deep.property('dpop_signing_alg_values_supported', ['ES256', 'PS256']);
      });
  });

  describe('userinfo', () => {
    it('validates the way DPoP proof JWT is provided', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'account',
        client: await this.provider.Client.find('client'),
        scope: 'openid',
      });
      at.setThumbprint('jkt', this.thumbprint);

      expect(() => at.setThumbprint('x5t', 'foo')).to.throw().with.property('error_description', 'multiple proof-of-posession mechanisms are not allowed');

      const dpop = await at.save();

      await this.agent.get('/me')
        .set('Authorization', `Bearer ${dpop}`)
        .expect(401)
        .expect({ error: 'invalid_token', error_description: 'invalid token provided' })
        .expect('WWW-Authenticate', /^DPoP /)
        .expect('WWW-Authenticate', /error="invalid_token"/)
        .expect('WWW-Authenticate', /algs="ES256 PS256"/);

      await this.agent.get('/me')
        .set('Authorization', `DPoP ${dpop}`)
        .expect(400)
        .expect({ error: 'invalid_request', error_description: '`DPoP` header not provided' })
        .expect('WWW-Authenticate', /^DPoP /)
        .expect('WWW-Authenticate', /algs="ES256 PS256"/);

      await this.agent.post('/me')
        .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/me')}`, 'POST', undefined, dpop))
        .send({ access_token: dpop })
        .type('form')
        .expect(400)
        .expect({ error: 'invalid_request', error_description: '`DPoP` tokens must be provided via an authorization header' })
        .expect('WWW-Authenticate', /^DPoP /)
        .expect('WWW-Authenticate', /algs="ES256 PS256"/);

      await this.agent.get('/me')
        .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/me')}`, 'GET', undefined, dpop))
        .set('Authorization', `Bearer ${dpop}`)
        .expect(400)
        .expect({ error: 'invalid_request', error_description: 'authorization header scheme must be `DPoP` when DPoP is used' })
        .expect('WWW-Authenticate', /^DPoP /)
        .expect('WWW-Authenticate', /algs="ES256 PS256"/);
    });

    context('validates the DPoP proof JWT is conform', () => {
      before(async function () {
        const at = new this.provider.AccessToken({
          accountId: this.loggedInAccountId,
          grantId: this.getGrantId(),
          client: await this.provider.Client.find('client'),
          scope: 'openid',
        });
        at.setThumbprint('jkt', this.thumbprint);

        this.access_token = await at.save();
        this.ath = createHash('sha256').update(this.access_token).digest('base64url');
      });

      afterEach(function () {
        this.provider.removeAllListeners('userinfo.error');
      });

      it('invalid typ', async function () {
        const spy = sinon.spy();
        this.provider.on('userinfo.error', spy);

        for (const value of ['JWT', 'secevent+jwt']) {
          await this.agent.get('/me') // eslint-disable-line no-await-in-loop
            .set('DPoP', await new SignJWT({}) // eslint-disable-line no-await-in-loop
              .setProtectedHeader({
                alg: 'ES256',
                jwk: this.jwk,
                typ: value,
              })
              .sign(this.keypair.privateKey))
            .set('Authorization', `DPoP ${this.access_token}`)
            .expect(401)
            .expect({ error: 'invalid_dpop_proof', error_description: 'invalid DPoP key binding' })
            .expect('WWW-Authenticate', /^DPoP /)
            .expect('WWW-Authenticate', /error="invalid_dpop_proof"/)
            .expect('WWW-Authenticate', /algs="ES256 PS256"/);
        }

        for (const { args: [, err] } of spy.getCalls()) {
          expect(err.error_detail).to.eql('unexpected "typ" JWT header value');
        }
      });

      it('alg mismatch', async function () {
        const spy = sinon.spy();
        this.provider.on('userinfo.error', spy);
        for (const value of [1, true, 'none', 'HS256', 'unsupported']) {
          await this.agent.get('/me') // eslint-disable-line no-await-in-loop
            .set('DPoP', `${base64url.encode(JSON.stringify({ jwk: this.jwk, typ: 'dpop+jwt', alg: value }))}.e30.`)
            .set('Authorization', `DPoP ${this.access_token}`)
            .expect(401)
            .expect({ error: 'invalid_dpop_proof', error_description: 'invalid DPoP key binding' })
            .expect('WWW-Authenticate', /^DPoP /)
            .expect('WWW-Authenticate', /error="invalid_dpop_proof"/)
            .expect('WWW-Authenticate', /algs="ES256 PS256"/);
        }

        for (const { args: [, err] } of spy.getCalls()) {
          expect(err.error_detail).to.be.oneOf(['"alg" (Algorithm) Header Parameter value not allowed', 'JWS "alg" (Algorithm) Header Parameter missing or invalid']);
        }
      });

      it('embedded jwk header', async function () {
        const spy = sinon.spy();
        this.provider.on('userinfo.error', spy);
        for (const value of [undefined, '', 1, true, null, 'foo', []]) {
          await this.agent.get('/me') // eslint-disable-line no-await-in-loop
            .set('DPoP', await new SignJWT({}) // eslint-disable-line no-await-in-loop
              .setProtectedHeader({
                alg: 'ES256',
                jwk: value,
                typ: 'dpop+jwt',
              })
              .sign(this.keypair.privateKey))
            .set('Authorization', `DPoP ${this.access_token}`)
            .expect(401)
            .expect({ error: 'invalid_dpop_proof', error_description: 'invalid DPoP key binding' })
            .expect('WWW-Authenticate', /^DPoP /)
            .expect('WWW-Authenticate', /error="invalid_dpop_proof"/)
            .expect('WWW-Authenticate', /algs="ES256 PS256"/);
        }

        for (const { args: [, err] } of spy.getCalls()) {
          expect(err.error_detail).to.eql('"jwk" (JSON Web Key) Header Parameter must be a JSON object');
        }
      });

      it('no private key in header', async function () {
        const spy = sinon.spy();
        this.provider.on('userinfo.error', spy);
        await this.agent.get('/me')
          .set('DPoP', await new SignJWT({})
            .setProtectedHeader({
              alg: 'ES256',
              jwk: await exportJWK(this.keypair.privateKey),
              typ: 'dpop+jwt',
            })
            .sign(this.keypair.privateKey))
          .set('Authorization', `DPoP ${this.access_token}`)
          .expect(401)
          .expect({ error: 'invalid_dpop_proof', error_description: 'invalid DPoP key binding' })
          .expect('WWW-Authenticate', /^DPoP /)
          .expect('WWW-Authenticate', /error="invalid_dpop_proof"/)
          .expect('WWW-Authenticate', /algs="ES256 PS256"/);

        for (const { args: [, err] } of spy.getCalls()) {
          expect(err.error_detail).to.eql('"jwk" (JSON Web Key) Header Parameter must be a public key');
        }
      });

      it('no symmetric key in header', async function () {
        const spy = sinon.spy();
        this.provider.on('userinfo.error', spy);
        await this.agent.get('/me') // eslint-disable-line no-await-in-loop
          .set('DPoP', await new SignJWT({})
            .setProtectedHeader({
              alg: 'ES256',
              jwk: await exportJWK(randomBytes(32)),
              typ: 'dpop+jwt',
            })
            .sign(this.keypair.privateKey))
          .set('Authorization', `DPoP ${this.access_token}`)
          .expect(401)
          .expect({ error: 'invalid_dpop_proof', error_description: 'invalid DPoP key binding' })
          .expect('WWW-Authenticate', /^DPoP /)
          .expect('WWW-Authenticate', /error="invalid_dpop_proof"/)
          .expect('WWW-Authenticate', /algs="ES256 PS256"/);

        for (const { args: [, err] } of spy.getCalls()) {
          expect(err.error_detail).to.eql('"jwk" (JSON Web Key) Header Parameter must be a public key');
        }
      });

      it('missing jti', async function () {
        await this.agent.get('/me') // eslint-disable-line no-await-in-loop
          .set('DPoP', await new SignJWT({ htm: 'POST', htu: `${this.provider.issuer}${this.suitePath('/me')}` })
            .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: this.jwk })
            .setIssuedAt()
            .sign(this.keypair.privateKey))
          .set('Authorization', `DPoP ${this.access_token}`)
          .expect(401)
          .expect({ error: 'invalid_dpop_proof', error_description: 'DPoP proof must have a jti string property' })
          .expect('WWW-Authenticate', /^DPoP /)
          .expect('WWW-Authenticate', /error="invalid_dpop_proof"/)
          .expect('WWW-Authenticate', /algs="ES256 PS256"/);
      });

      it('htm mismatch', async function () {
        await this.agent.get('/me') // eslint-disable-line no-await-in-loop
          .set('DPoP', await new SignJWT({ htm: 'POST', htu: `${this.provider.issuer}${this.suitePath('/me')}`, ath: this.ath })
            .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: this.jwk })
            .setIssuedAt()
            .setJti(randomUUID())
            .sign(this.keypair.privateKey))
          .set('Authorization', `DPoP ${this.access_token}`)
          .expect(401)
          .expect({ error: 'invalid_dpop_proof', error_description: 'DPoP proof htm mismatch' })
          .expect('WWW-Authenticate', /^DPoP /)
          .expect('WWW-Authenticate', /error="invalid_dpop_proof"/)
          .expect('WWW-Authenticate', /algs="ES256 PS256"/);
      });

      it('htu mismatch', async function () {
        await this.agent.get('/me') // eslint-disable-line no-await-in-loop
          .set('DPoP', await new SignJWT({ htm: 'GET', htu: `${this.provider.issuer}${this.suitePath('/token')}`, ath: this.ath })
            .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: this.jwk })
            .setIssuedAt()
            .setJti(randomUUID())
            .sign(this.keypair.privateKey))
          .set('Authorization', `DPoP ${this.access_token}`)
          .expect(401)
          .expect({ error: 'invalid_dpop_proof', error_description: 'DPoP proof htu mismatch' })
          .expect('WWW-Authenticate', /^DPoP /)
          .expect('WWW-Authenticate', /error="invalid_dpop_proof"/)
          .expect('WWW-Authenticate', /algs="ES256 PS256"/);
      });

      it('iat too old', async function () {
        await this.agent.get('/me') // eslint-disable-line no-await-in-loop
          .set('DPoP', await new SignJWT({ htm: 'GET', htu: `${this.provider.issuer}${this.suitePath('/me')}`, ath: this.ath })
            .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: this.jwk })
            .setIssuedAt(epochTime() - 301)
            .setJti(randomUUID())
            .sign(this.keypair.privateKey))
          .set('Authorization', `DPoP ${this.access_token}`)
          .expect(401)
          .expect({ error: 'invalid_dpop_proof', error_description: 'DPoP proof iat is not recent enough' })
          .expect('WWW-Authenticate', /^DPoP /)
          .expect('WWW-Authenticate', /error="invalid_dpop_proof"/)
          .expect('WWW-Authenticate', /algs="ES256 PS256"/);
      });

      it('iat too in the future', async function () {
        await this.agent.get('/me') // eslint-disable-line no-await-in-loop
          .set('DPoP', await new SignJWT({ htm: 'GET', htu: `${this.provider.issuer}${this.suitePath('/me')}`, ath: this.ath })
            .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: this.jwk })
            .setIssuedAt(epochTime() + 301)
            .setJti(randomUUID())
            .sign(this.keypair.privateKey))
          .set('Authorization', `DPoP ${this.access_token}`)
          .expect(401)
          .expect({ error: 'invalid_dpop_proof', error_description: 'DPoP proof iat is not recent enough' })
          .expect('WWW-Authenticate', /^DPoP /)
          .expect('WWW-Authenticate', /error="invalid_dpop_proof"/)
          .expect('WWW-Authenticate', /algs="ES256 PS256"/);
      });
    });

    it('acts like an RS checking the DPoP proof and thumbprint now', async function () {
      const at = new this.provider.AccessToken({
        accountId: this.loggedInAccountId,
        grantId: this.getGrantId(),
        client: await this.provider.Client.find('client'),
        scope: 'openid',
      });
      at.setThumbprint('jkt', this.thumbprint);

      const dpop = await at.save();
      const proof = await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/me')}`, 'GET', undefined, dpop);

      await this.agent.get('/me')
        .set('Authorization', `DPoP ${dpop}`)
        .set('DPoP', proof)
        .expect(200);

      let spy = sinon.spy();
      this.provider.once('userinfo.error', spy);

      await this.agent.get('/me')
        .set('Authorization', `DPoP ${dpop}`)
        .set('DPoP', proof)
        .expect(401)
        .expect({ error: 'invalid_token', error_description: 'invalid token provided' });

      expect(spy).to.have.property('calledOnce', true);
      expect(spy.args[0][1]).to.have.property('error_detail', 'DPoP proof JWT Replay detected');

      spy = sinon.spy();
      this.provider.once('userinfo.error', spy);

      await this.agent.get('/me')
        .set('Authorization', `DPoP ${dpop}`)
        .set('DPoP', await DPoP(await generateKeyPair('ES256'), `${this.provider.issuer}${this.suitePath('/me')}`, 'GET', undefined, dpop))
        .expect({ error: 'invalid_token', error_description: 'invalid token provided' })
        .expect(401);

      await this.agent.get('/me')
        .set('Authorization', `DPoP ${dpop}`)
        .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/me')}`, 'GET', undefined, 'anotherAccessTokenValue'))
        .expect({ error: 'invalid_dpop_proof', error_description: 'DPoP proof ath mismatch' })
        .expect(401);

      expect(spy).to.have.property('calledOnce', true);
      expect(spy.args[0][1]).to.have.property('error_detail', 'failed jkt verification');

      spy = sinon.spy();
      this.provider.once('userinfo.error', spy);

      await this.agent.get('/me')
        .set('Authorization', `Bearer ${dpop}`)
        .expect({ error: 'invalid_token', error_description: 'invalid token provided' })
        .expect(401);

      expect(spy).to.have.property('calledOnce', true);
      expect(spy.args[0][1]).to.have.property('error_detail', 'failed jkt verification');
    });
  });

  describe('introspection', () => {
    it('exposes cnf and DPoP proof JWT type now', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'account',
        client: await this.provider.Client.find('client'),
        scope: 'openid',
      });
      at.setThumbprint('jkt', this.thumbprint);

      const token = await at.save();

      await this.agent.post('/token/introspection')
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(200)
        .expect(({ body }) => {
          expect(body).to.have.property('cnf');
          expect(body).to.have.property('token_type', 'DPoP');
          expect(body.cnf).to.have.property('jkt');
        });
    });
  });

  describe('urn:ietf:params:oauth:grant-type:device_code', () => {
    beforeEach(async function () {
      await this.agent.post('/device/auth')
        .auth('client', 'secret')
        .send({ scope: 'openid' })
        .type('form')
        .expect(200)
        .expect(({ body: { device_code: dc } }) => {
          this.dc = dc;
        });

      this.TestAdapter.for('DeviceCode').syncUpdate(this.getTokenJti(this.dc), {
        scope: 'openid offline_access',
        accountId: this.loggedInAccountId,
        grantId: this.getGrantId(),
      });
    });

    it('binds the access token to the jwk', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.success', spy);

      await this.agent.post('/token')
        .auth('client', 'secret')
        .send({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: this.dc,
        })
        .type('form')
        .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/token')}`, 'POST'))
        .expect(200);

      expect(spy).to.have.property('calledOnce', true);
      const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
      expect(AccessToken).to.have.property('jkt', this.thumbprint);
      expect(RefreshToken).not.to.have.property('jkt');
    });

    it('binds the refresh token to the jwk for public clients', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.success', spy);

      // changes the code to client-none
      this.TestAdapter.for('DeviceCode').syncUpdate(this.getTokenJti(this.dc), {
        clientId: 'client-none',
        accountId: this.loggedInAccountId,
        grantId: this.getGrantId('client-none'),
      });

      await this.agent.post('/token')
        .send({
          client_id: 'client-none',
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: this.dc,
        })
        .type('form')
        .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/token')}`, 'POST'))
        .expect(200);

      expect(spy).to.have.property('calledOnce', true);
      const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
      expect(AccessToken).to.have.property('jkt', this.thumbprint);
      expect(RefreshToken).to.have.property('jkt', this.thumbprint);
    });
  });

  describe('urn:openid:params:grant-type:ciba', () => {
    beforeEach(async function () {
      await this.agent.post('/backchannel')
        .auth('client', 'secret')
        .send({
          scope: 'openid offline_access',
          login_hint: 'accountId',
        })
        .type('form')
        .expect(200)
        .expect(({ body: { auth_req_id: reqId } }) => {
          this.reqId = reqId;
        });
    });

    it('binds the access token to the jwk', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.success', spy);

      await this.agent.post('/token')
        .auth('client', 'secret')
        .send({
          grant_type: 'urn:openid:params:grant-type:ciba',
          auth_req_id: this.reqId,
        })
        .type('form')
        .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/token')}`, 'POST'))
        .expect(200);

      expect(spy).to.have.property('calledOnce', true);
      const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
      expect(AccessToken).to.have.property('jkt', this.thumbprint);
      expect(RefreshToken).not.to.have.property('jkt');
    });

    it('binds the refresh token to the jwk for public clients', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.success', spy);

      // changes the code to client-none
      this.TestAdapter.for('BackchannelAuthenticationRequest').syncUpdate(this.getTokenJti(this.reqId), {
        clientId: 'client-none',
      });
      const { grantId } = this.TestAdapter.for('BackchannelAuthenticationRequest').syncFind(this.getTokenJti(this.reqId));
      this.TestAdapter.for('Grant').syncUpdate(grantId, {
        clientId: 'client-none',
      });

      await this.agent.post('/token')
        .send({
          client_id: 'client-none',
          grant_type: 'urn:openid:params:grant-type:ciba',
          auth_req_id: this.reqId,
        })
        .type('form')
        .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/token')}`, 'POST'))
        .expect(200);

      expect(spy).to.have.property('calledOnce', true);
      const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
      expect(AccessToken).to.have.property('jkt', this.thumbprint);
      expect(RefreshToken).to.have.property('jkt', this.thumbprint);
    });
  });

  describe('pushed authorization request', () => {
    it('checks dpop_jkt equals the jwk thumbprint when both are present', async function () {
      await this.agent.post('/request')
        .auth('client', 'secret')
        .send({
          response_type: 'code',
          client_id: 'client',
          dpop_jkt: this.thumbprint,
        })
        .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/request')}`, 'POST'))
        .type('form')
        .expect(201);

      await this.agent.post('/request')
        .auth('client', 'secret')
        .send({
          response_type: 'code',
          client_id: 'client',
          dpop_jkt: 'cbaZgHZazjgQq0Q2-Hy_o2-OCDpPu02S30lNhTsNU1Q',
        })
        .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/request')}`, 'POST'))
        .type('form')
        .expect(400)
        .expect({ error: 'invalid_request', error_description: 'DPoP proof key thumbprint does not match dpop_jkt' });
    });

    it('sets the request dpop_jkt automatically when missing (no request object used)', async function () {
      let request_uri;
      await this.agent.post('/request')
        .auth('client', 'secret')
        .send({
          scope: 'openid',
          response_type: 'code',
          client_id: 'client',
        })
        .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/request')}`, 'POST'))
        .type('form')
        .expect(201)
        .expect(({ body }) => {
          ({ request_uri } = body);
        });

      const auth = new this.AuthorizationRequest({
        request_uri,
      });

      let code;
      await this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validateClientLocation)
        .expect(({ headers: { location } }) => {
          ({ query: { code } } = url.parse(location, true));
        });

      const { dpopJkt } = this.TestAdapter.for('AuthorizationCode').syncFind(code);
      expect(dpopJkt).to.be.a('string').of.length(43);
    });

    it('sets the request dpop_jkt automatically when missing (request object used)', async function () {
      let request_uri;
      await this.agent.post('/request')
        .auth('client', 'secret')
        .send({
          client_id: 'client',
          request: await new SignJWT({
            client_id: 'client',
            scope: 'openid',
            response_type: 'code',
            iss: 'client',
            aud: this.provider.issuer,
          })
            .setProtectedHeader({ alg: 'HS256' })
            .setIssuedAt()
            .setIssuer('client')
            .setAudience(this.provider.issuer)
            .setExpirationTime('1m')
            .setNotBefore('0s')
            .sign(Buffer.from('secret')),
        })
        .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/request')}`, 'POST'))
        .type('form')
        .expect(201)
        .expect(({ body }) => {
          ({ request_uri } = body);
        });

      const auth = new this.AuthorizationRequest({
        request_uri,
      });

      let code;
      await this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validateClientLocation)
        .expect(({ headers: { location } }) => {
          ({ query: { code } } = url.parse(location, true));
        });

      const { dpopJkt } = this.TestAdapter.for('AuthorizationCode').syncFind(code);
      expect(dpopJkt).to.be.a('string').of.length(43);
    });
  });

  describe('authorization flow', () => {
    describe('without dpop_jkt', () => {
      beforeEach(async function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid offline_access',
          prompt: 'consent',
        });

        await this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(303)
          .expect(auth.validateClientLocation)
          .expect(({ headers: { location } }) => {
            const { query: { code } } = url.parse(location, true);
            this.code = code;
          });
      });

      describe('authorization_code', () => {
        it('binds the access token to the jwk', async function () {
          const spy = sinon.spy();
          this.provider.once('grant.success', spy);

          await this.agent.post('/token')
            .auth('client', 'secret')
            .send({
              grant_type: 'authorization_code',
              code: this.code,
              redirect_uri: 'https://client.example.com/cb',
            })
            .type('form')
            .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/token')}`, 'POST'))
            .expect(200);

          expect(spy).to.have.property('calledOnce', true);
          const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
          expect(AccessToken).to.have.property('jkt', this.thumbprint);
          expect(RefreshToken).not.to.have.property('jkt');
        });
      });
    });

    describe('with dpop_jkt', () => {
      beforeEach(async function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid offline_access',
          prompt: 'consent',
          dpop_jkt: this.thumbprint,
        });

        await this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(303)
          .expect(auth.validateClientLocation)
          .expect(({ headers: { location } }) => {
            const { query: { code } } = url.parse(location, true);
            this.code = code;
          });
      });

      describe('authorization_code', () => {
        it('binds the access token to the jwk', async function () {
          const spy = sinon.spy();
          this.provider.once('grant.success', spy);

          await this.agent.post('/token')
            .auth('client', 'secret')
            .send({
              grant_type: 'authorization_code',
              code: this.code,
              redirect_uri: 'https://client.example.com/cb',
            })
            .type('form')
            .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/token')}`, 'POST'))
            .expect(200);

          expect(spy).to.have.property('calledOnce', true);
          const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
          expect(AccessToken).to.have.property('jkt', this.thumbprint);
          expect(RefreshToken).not.to.have.property('jkt');
        });

        it('checks the dpop_jkt matches the proof jwk thumbprint', async function () {
          const spy = sinon.spy();
          this.provider.once('grant.error', spy);

          await this.agent.post('/token')
            .auth('client', 'secret')
            .send({
              grant_type: 'authorization_code',
              code: this.code,
              redirect_uri: 'https://client.example.com/cb',
            })
            .type('form')
            .set('DPoP', await DPoP(await generateKeyPair('ES256'), `${this.provider.issuer}${this.suitePath('/token')}`, 'POST'))
            .expect(400)
            .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

          expect(spy).to.have.property('calledOnce', true);
          expect(spy.args[0][1]).to.have.property('error_detail', 'DPoP proof key thumbprint does not match dpop_jkt');
        });

        it('requires dpop to be used when dpop_jkt was present', async function () {
          const spy = sinon.spy();
          this.provider.once('grant.error', spy);

          await this.agent.post('/token')
            .auth('client', 'secret')
            .send({
              grant_type: 'authorization_code',
              code: this.code,
              redirect_uri: 'https://client.example.com/cb',
            })
            .type('form')
            .expect(400)
            .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

          expect(spy).to.have.property('calledOnce', true);
          expect(spy.args[0][1]).to.have.property('error_detail', 'missing DPoP proof JWT');
        });
      });
    });

    describe('refresh_token', () => {
      beforeEach(async function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid offline_access',
          prompt: 'consent',
        });

        await this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(303)
          .expect(auth.validateClientLocation)
          .expect(({ headers: { location } }) => {
            const { query: { code } } = url.parse(location, true);
            this.code = code;
          });

        await this.agent.post('/token')
          .auth('client', 'secret')
          .send({
            grant_type: 'authorization_code',
            code: this.code,
            redirect_uri: 'https://client.example.com/cb',
          })
          .type('form')
          .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/token')}`, 'POST'))
          .expect(({ body }) => {
            this.rt = body.refresh_token;
          });
      });

      it('binds the access token to the jwk', async function () {
        const spy = sinon.spy();
        this.provider.once('grant.success', spy);

        await this.agent.post('/token')
          .auth('client', 'secret')
          .send({
            grant_type: 'refresh_token',
            refresh_token: this.rt,
          })
          .type('form')
          .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/token')}`, 'POST'))
          .expect(200);

        expect(spy).to.have.property('calledOnce', true);
        const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
        expect(AccessToken).to.have.property('jkt', this.thumbprint);
        expect(RefreshToken.jkt).to.be.undefined;
      });
    });
  });

  describe('authorization flow (public client)', () => {
    beforeEach(async function () {
      const auth = new this.AuthorizationRequest({
        client_id: 'client-none',
        response_type: 'code',
        scope: 'openid offline_access',
        prompt: 'consent',
      });

      await this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validateClientLocation)
        .expect(({ headers: { location } }) => {
          const { query: { code } } = url.parse(location, true);
          this.code = code;
        });
    });

    describe('authorization_code', () => {
      it('binds the access token to the jwk', async function () {
        const spy = sinon.spy();
        this.provider.once('grant.success', spy);

        await this.agent.post('/token')
          .send({
            client_id: 'client-none',
            grant_type: 'authorization_code',
            code: this.code,
            redirect_uri: 'https://client.example.com/cb',
          })
          .type('form')
          .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/token')}`, 'POST'))
          .expect(200);

        expect(spy).to.have.property('calledOnce', true);
        const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
        expect(AccessToken).to.have.property('jkt', this.thumbprint);
        expect(RefreshToken).to.have.property('jkt', this.thumbprint);
      });
    });

    describe('refresh_token', () => {
      beforeEach(async function () {
        await this.agent.post('/token')
          .send({
            client_id: 'client-none',
            grant_type: 'authorization_code',
            code: this.code,
            redirect_uri: 'https://client.example.com/cb',
          })
          .type('form')
          .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/token')}`, 'POST'))
          .expect(({ body }) => {
            this.rt = body.refresh_token;
          });
      });

      it('binds the access token to the jwk', async function () {
        const spy = sinon.spy();
        this.provider.once('grant.success', spy);

        await this.agent.post('/token')
          .send({
            client_id: 'client-none',
            grant_type: 'refresh_token',
            refresh_token: this.rt,
          })
          .type('form')
          .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/token')}`, 'POST'))
          .expect(200);

        expect(spy).to.have.property('calledOnce', true);
        const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
        expect(AccessToken).to.have.property('jkt', this.thumbprint);
        expect(RefreshToken).to.have.property('jkt', this.thumbprint);
      });

      it('verifies the request made with the same cert jwk', async function () {
        const spy = sinon.spy();
        this.provider.once('grant.error', spy);

        await this.agent.post('/token')
          .send({
            client_id: 'client-none',
            grant_type: 'refresh_token',
            refresh_token: this.rt,
          })
          .set('DPoP', await DPoP(await generateKeyPair('ES256'), `${this.provider.issuer}${this.suitePath('/token')}`, 'POST'))
          .type('form')
          .expect(400)
          .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

        expect(spy).to.have.property('calledOnce', true);
        expect(spy.args[0][1]).to.have.property('error_detail', 'failed jkt verification');
      });
    });
  });

  describe('client_credentials', () => {
    it('binds the access token to the jwk', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.success', spy);

      await this.agent.post('/token')
        .auth('client', 'secret')
        .send({ grant_type: 'client_credentials' })
        .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/token')}`, 'POST'))
        .type('form')
        .expect(200);

      expect(spy).to.have.property('calledOnce', true);
      const { oidc: { entities: { ClientCredentials } } } = spy.args[0][0];
      expect(ClientCredentials).to.have.property('jkt', this.thumbprint);
    });
  });

  describe('status codes at the token endpoint', () => {
    it('should be 400 for invalid_dpop_proof', async function () {
      return this.agent.post('/token')
        .auth('client', 'secret')
        .send({ grant_type: 'client_credentials' })
        .set('DPoP', 'invalid')
        .type('form')
        .expect(400)
        .expect({ error: 'invalid_dpop_proof', error_description: 'invalid DPoP key binding' });
    });
  });

  describe('invalid nonce', () => {
    it('@ userinfo', async function () {
      let nonce;
      await this.agent.get('/me')
        .set('Authorization', 'DPoP foo')
        .send({ grant_type: 'client_credentials' })
        .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/me')}`, 'GET', 'foo', 'foo'))
        .expect(401)
        .expect({ error: 'use_dpop_nonce', error_description: 'invalid nonce in DPoP proof' })
        .expect(({ headers }) => { nonce = headers['dpop-nonce']; });

      return this.agent.get('/me')
        .set('Authorization', 'DPoP foo')
        .send({ grant_type: 'client_credentials' })
        .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/me')}`, 'GET', nonce, 'foo'))
        .expect(401)
        .expect({ error: 'invalid_token', error_description: 'invalid token provided' });
    });

    it('@ token endpoint', async function () {
      let nonce;
      await this.agent.post('/token')
        .auth('client', 'secret')
        .send({ grant_type: 'client_credentials' })
        .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/token')}`, 'POST', 'foo'))
        .type('form')
        .expect(400)
        .expect({ error: 'use_dpop_nonce', error_description: 'invalid nonce in DPoP proof' })
        .expect(({ headers }) => { nonce = headers['dpop-nonce']; });

      return this.agent.post('/token')
        .auth('client', 'secret')
        .send({ grant_type: 'client_credentials' })
        .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/token')}`, 'POST', nonce))
        .type('form')
        .expect(200);
    });
  });

  describe('required nonce', () => {
    before(function () {
      this.orig = i(this.provider).configuration().features.dPoP.requireNonce;
      i(this.provider).configuration().features.dPoP.requireNonce = () => true;
    });

    after(function () {
      i(this.provider).configuration().features.dPoP.requireNonce = this.orig;
    });

    it('@ PAR endpoint', async function () {
      let nonce;
      await this.agent.post('/request')
        .auth('client', 'secret')
        .send({
          response_type: 'code',
          client_id: 'client',
        })
        .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/request')}`, 'POST'))
        .type('form')
        .expect(400)
        .expect('dpop-nonce', /^[\w-]{43}$/)
        .expect({ error: 'use_dpop_nonce', error_description: 'nonce is required in the DPoP proof' })
        .expect(({ headers }) => { nonce = headers['dpop-nonce']; });

      await this.agent.post('/request')
        .auth('client', 'secret')
        .send({
          response_type: 'code',
          client_id: 'client',
        })
        .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/request')}`, 'POST', nonce))
        .type('form')
        .expect(201);
    });

    it('@ userinfo', async function () {
      let nonce;
      await this.agent.get('/me')
        .set('Authorization', 'DPoP foo')
        .send({ grant_type: 'client_credentials' })
        .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/me')}`, 'GET', undefined, 'foo'))
        .expect(401)
        .expect({ error: 'use_dpop_nonce', error_description: 'nonce is required in the DPoP proof' })
        .expect(({ headers }) => { nonce = headers['dpop-nonce']; });

      return this.agent.get('/me')
        .set('Authorization', 'DPoP foo')
        .send({ grant_type: 'client_credentials' })
        .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/me')}`, 'GET', nonce, 'foo'))
        .expect(401)
        .expect({ error: 'invalid_token', error_description: 'invalid token provided' });
    });

    it('@ token endpoint', async function () {
      let nonce;
      await this.agent.post('/token')
        .auth('client', 'secret')
        .send({ grant_type: 'client_credentials' })
        .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/token')}`, 'POST'))
        .type('form')
        .expect(400)
        .expect({ error: 'use_dpop_nonce', error_description: 'nonce is required in the DPoP proof' })
        .expect(({ headers }) => { nonce = headers['dpop-nonce']; });

      return this.agent.post('/token')
        .auth('client', 'secret')
        .send({ grant_type: 'client_credentials' })
        .set('DPoP', await DPoP(this.keypair, `${this.provider.issuer}${this.suitePath('/token')}`, 'POST', nonce))
        .type('form')
        .expect(200);
    });
  });
});
