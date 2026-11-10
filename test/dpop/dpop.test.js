import { describe, before, it, afterEach, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import * as url from 'node:url';
import { hash, randomBytes, randomUUID } from 'node:crypto';

import sinon from 'sinon';
import timekeeper from 'timekeeper';
import {
  SignJWT, exportJWK, calculateJwkThumbprint, decodeJwt, generateKeyPair,
} from 'jose';

import nanoid from '../../lib/helpers/nanoid.js';
import epochTime from '../../lib/helpers/epoch_time.js';
import { CHALLENGE_OK_WINDOW } from '../../lib/helpers/challenge.js';
import { InvalidGrant, InvalidRequest, InvalidToken } from '../../lib/helpers/errors.js';
import bootstrap, { skipConsent } from '../test_helper.js';
import * as base64url from '../../lib/helpers/base64url.js';

function ath(accessToken) {
  return hash('sha256', accessToken, 'base64url');
}

async function DPoP(keypair, htu, htm, nonce = undefined, accessToken = undefined, iat = epochTime()) {
  return new SignJWT({
    htu,
    htm,
    nonce,
    ath: accessToken ? ath(accessToken) : undefined,
  }).setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: await exportJWK(keypair.publicKey) })
    .setJti(nanoid())
    .setIssuedAt(iat)
    .sign(keypair.privateKey);
}

describe('features.dPoP', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });
  before(() => fixture.login({ scope: 'openid offline_access' }), { timeout: 3000 });
  skipConsent(fixture);
  before(async () => {
    fixture.keypair = await generateKeyPair('ES256', { extractable: true });
    fixture.jwk = await exportJWK(fixture.keypair.publicKey);
    fixture.thumbprint = await calculateJwkThumbprint(fixture.jwk);
  }, { timeout: 3000 });

  it('extends discovery', { timeout: 3000 }, async () => {
    await fixture.agent.get('/.well-known/openid-configuration')
      .expect(200)
      .expect((response) => {
        ((actual) => { assert.ok('dpop_signing_alg_values_supported' in Object(actual)); assert.deepEqual(actual.dpop_signing_alg_values_supported, ['ES256', 'PS256']); })(response.body);
      });
  });

  describe('userinfo', () => {
    const fixture1 = Object.create(fixture);

    it('validates the way DPoP proof JWT is provided', { timeout: 3000 }, async () => {
      const at = new fixture1.provider.AccessToken({
        accountId: 'account',
        client: await fixture1.provider.Client.find('client'),
        scope: 'openid',
      });
      at.setThumbprint('jkt', fixture1.thumbprint);

      ((actual) => { assert.throws(actual, (error) => { assert.ok('error_description' in Object(error)); assert.equal(error.error_description, 'multiple proof-of-possession mechanisms are not allowed'); return true; }); })(() => at.setThumbprint('x5t', 'foo'));

      const dpop = await at.save();

      await fixture1.agent.get('/me')
        .set('Authorization', `Bearer ${dpop}`)
        .expect(401)
        .expect({ error: 'invalid_token', error_description: 'invalid token provided' })
        .expect('WWW-Authenticate', /^DPoP /)
        .expect('WWW-Authenticate', /error="invalid_token"/)
        .expect('WWW-Authenticate', /algs="ES256 PS256"/);

      await fixture1.agent.get('/me')
        .set('Authorization', `DPoP ${dpop}`)
        .expect(400)
        .expect({ error: 'invalid_request', error_description: '`DPoP` header not provided' })
        .expect('WWW-Authenticate', /^DPoP /)
        .expect('WWW-Authenticate', /algs="ES256 PS256"/);

      await fixture1.agent.post('/me')
        .set('DPoP', await DPoP(fixture1.keypair, `${fixture1.provider.issuer}${fixture1.suitePath('/me')}`, 'POST', undefined, dpop))
        .send({ access_token: dpop })
        .type('form')
        .expect(400)
        .expect({ error: 'invalid_request', error_description: '`DPoP` tokens must be provided via an authorization header' })
        .expect('WWW-Authenticate', /^DPoP /)
        .expect('WWW-Authenticate', /algs="ES256 PS256"/);

      await fixture1.agent.get('/me')
        .set('DPoP', await DPoP(fixture1.keypair, `${fixture1.provider.issuer}${fixture1.suitePath('/me')}`, 'GET', undefined, dpop))
        .set('Authorization', `Bearer ${dpop}`)
        .expect(400)
        .expect({ error: 'invalid_request', error_description: 'authorization header scheme must be `DPoP` when DPoP is used' })
        .expect('WWW-Authenticate', /^DPoP /)
        .expect('WWW-Authenticate', /algs="ES256 PS256"/);
    });

    describe('validates the DPoP proof JWT is conform', () => {
      const fixture2 = Object.create(fixture1);

      before(async () => {
        const at = new fixture2.provider.AccessToken({
          accountId: fixture2.loggedInAccountId,
          grantId: fixture2.getGrantId(),
          client: await fixture2.provider.Client.find('client'),
          scope: 'openid',
        });
        at.setThumbprint('jkt', fixture2.thumbprint);

        fixture2.access_token = await at.save();
        fixture2.ath = hash('sha256', fixture2.access_token, 'base64url');
      }, { timeout: 3000 });

      afterEach(() => {
        fixture2.provider.removeAllListeners('userinfo.error');
      }, { timeout: 3000 });

      it('invalid typ', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture2.provider.on('userinfo.error', spy);

        for (const value of ['JWT', 'secevent+jwt']) {
          await fixture2.agent.get('/me')
            .set('DPoP', await new SignJWT({})
              .setProtectedHeader({
                alg: 'ES256',
                jwk: fixture2.jwk,
                typ: value,
              })
              .sign(fixture2.keypair.privateKey))
            .set('Authorization', `DPoP ${fixture2.access_token}`)
            .expect(401)
            .expect({ error: 'invalid_dpop_proof', error_description: 'invalid DPoP key binding' })
            .expect('WWW-Authenticate', /^DPoP /)
            .expect('WWW-Authenticate', /error="invalid_dpop_proof"/)
            .expect('WWW-Authenticate', /algs="ES256 PS256"/)
            .expect((response) => {
              assert.ok(!(response.headers['www-authenticate'].includes('error_detail')));
              assert.ok(!(response.headers['www-authenticate'].includes('cause')));
            });
        }

        for (const { args: [, err] } of spy.getCalls()) {
          assert.deepEqual(err.error_detail, 'unexpected "typ" JWT header value');
          assert.ok(err.cause instanceof Error);
          assert.equal(err.cause.message, err.error_detail);
        }
      });

      it('alg mismatch', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture2.provider.on('userinfo.error', spy);
        for (const value of [1, true, 'none', 'HS256', 'unsupported']) {
          await fixture2.agent.get('/me')
            .set('DPoP', `${base64url.encode(JSON.stringify({ jwk: fixture2.jwk, typ: 'dpop+jwt', alg: value }))}.e30.`)
            .set('Authorization', `DPoP ${fixture2.access_token}`)
            .expect(401)
            .expect({ error: 'invalid_dpop_proof', error_description: 'invalid DPoP key binding' })
            .expect('WWW-Authenticate', /^DPoP /)
            .expect('WWW-Authenticate', /error="invalid_dpop_proof"/)
            .expect('WWW-Authenticate', /algs="ES256 PS256"/);
        }

        for (const { args: [, err] } of spy.getCalls()) {
          assert.ok(['"alg" (Algorithm) Header Parameter value not allowed', 'JWS "alg" (Algorithm) Header Parameter missing or invalid'].includes(err.error_detail));
        }
      });

      it('embedded jwk header', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture2.provider.on('userinfo.error', spy);
        for (const value of [undefined, '', 1, true, null, 'foo', []]) {
          await fixture2.agent.get('/me')
            .set('DPoP', await new SignJWT({})
              .setProtectedHeader({
                alg: 'ES256',
                jwk: value,
                typ: 'dpop+jwt',
              })
              .sign(fixture2.keypair.privateKey))
            .set('Authorization', `DPoP ${fixture2.access_token}`)
            .expect(401)
            .expect({ error: 'invalid_dpop_proof', error_description: 'invalid DPoP key binding' })
            .expect('WWW-Authenticate', /^DPoP /)
            .expect('WWW-Authenticate', /error="invalid_dpop_proof"/)
            .expect('WWW-Authenticate', /algs="ES256 PS256"/);
        }

        for (const { args: [, err] } of spy.getCalls()) {
          assert.deepEqual(err.error_detail, '"jwk" (JSON Web Key) Header Parameter must be a JSON object');
        }
      });

      it('no private key in header', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture2.provider.on('userinfo.error', spy);
        await fixture2.agent.get('/me')
          .set('DPoP', await new SignJWT({})
            .setProtectedHeader({
              alg: 'ES256',
              jwk: await exportJWK(fixture2.keypair.privateKey),
              typ: 'dpop+jwt',
            })
            .sign(fixture2.keypair.privateKey))
          .set('Authorization', `DPoP ${fixture2.access_token}`)
          .expect(401)
          .expect({ error: 'invalid_dpop_proof', error_description: 'invalid DPoP key binding' })
          .expect('WWW-Authenticate', /^DPoP /)
          .expect('WWW-Authenticate', /error="invalid_dpop_proof"/)
          .expect('WWW-Authenticate', /algs="ES256 PS256"/);
      });

      it('no symmetric key in header', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture2.provider.on('userinfo.error', spy);
        await fixture2.agent.get('/me')
          .set('DPoP', await new SignJWT({})
            .setProtectedHeader({
              alg: 'ES256',
              jwk: await exportJWK(randomBytes(32)),
              typ: 'dpop+jwt',
            })
            .sign(fixture2.keypair.privateKey))
          .set('Authorization', `DPoP ${fixture2.access_token}`)
          .expect(401)
          .expect({ error: 'invalid_dpop_proof', error_description: 'invalid DPoP key binding' })
          .expect('WWW-Authenticate', /^DPoP /)
          .expect('WWW-Authenticate', /error="invalid_dpop_proof"/)
          .expect('WWW-Authenticate', /algs="ES256 PS256"/);
      });

      it('missing jti', { timeout: 3000 }, async () => {
        await fixture2.agent.get('/me')
          .set('DPoP', await new SignJWT({ htm: 'POST', htu: `${fixture2.provider.issuer}${fixture2.suitePath('/me')}` })
            .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: fixture2.jwk })
            .setIssuedAt()
            .sign(fixture2.keypair.privateKey))
          .set('Authorization', `DPoP ${fixture2.access_token}`)
          .expect(401)
          .expect({ error: 'invalid_dpop_proof', error_description: 'DPoP proof must have a jti string property' })
          .expect('WWW-Authenticate', /^DPoP /)
          .expect('WWW-Authenticate', /error="invalid_dpop_proof"/)
          .expect('WWW-Authenticate', /algs="ES256 PS256"/);
      });

      it('htm mismatch', { timeout: 3000 }, async () => {
        await fixture2.agent.get('/me')
          .set('DPoP', await new SignJWT({ htm: 'POST', htu: `${fixture2.provider.issuer}${fixture2.suitePath('/me')}`, ath: fixture2.ath })
            .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: fixture2.jwk })
            .setIssuedAt()
            .setJti(randomUUID())
            .sign(fixture2.keypair.privateKey))
          .set('Authorization', `DPoP ${fixture2.access_token}`)
          .expect(401)
          .expect({ error: 'invalid_dpop_proof', error_description: 'DPoP proof htm mismatch' })
          .expect('WWW-Authenticate', /^DPoP /)
          .expect('WWW-Authenticate', /error="invalid_dpop_proof"/)
          .expect('WWW-Authenticate', /algs="ES256 PS256"/);
      });

      it('htu mismatch', { timeout: 3000 }, async () => {
        await fixture2.agent.get('/me')
          .set('DPoP', await new SignJWT({ htm: 'GET', htu: `${fixture2.provider.issuer}${fixture2.suitePath('/token')}`, ath: fixture2.ath })
            .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: fixture2.jwk })
            .setIssuedAt()
            .setJti(randomUUID())
            .sign(fixture2.keypair.privateKey))
          .set('Authorization', `DPoP ${fixture2.access_token}`)
          .expect(401)
          .expect({ error: 'invalid_dpop_proof', error_description: 'DPoP proof htu mismatch' })
          .expect('WWW-Authenticate', /^DPoP /)
          .expect('WWW-Authenticate', /error="invalid_dpop_proof"/)
          .expect('WWW-Authenticate', /algs="ES256 PS256"/);
      });

      for (const enabled of [true, false]) {
        describe(`with DPoP-Nonces ${enabled ? 'enabled' : 'disabled'}`, () => {
          const fixture3 = Object.create(fixture2);

          before(() => {
            ({ DPoPNonces: fixture3.DPoPNonces } = i(fixture3.provider));
            if (enabled) {
              i(fixture3.provider).DPoPNonces = fixture3.DPoPNonces;
            } else {
              i(fixture3.provider).DPoPNonces = undefined;
            }
          }, { timeout: 3000 });

          after(() => {
            i(fixture3.provider).DPoPNonces = fixture3.DPoPNonces;
          }, { timeout: 3000 });

          for (const offset of [301, -301]) {
            it(`iat too ${offset > 0 ? 'far in the future' : 'old'}`, { timeout: 3000 }, async () => {
              await fixture3.agent.get('/me')
                .set('DPoP', await new SignJWT({ htm: 'GET', htu: `${fixture3.provider.issuer}${fixture3.suitePath('/me')}`, ath: fixture3.ath })
                  .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: fixture3.jwk })
                  .setIssuedAt(epochTime() - 301)
                  .setJti(randomUUID())
                  .sign(fixture3.keypair.privateKey))
                .set('Authorization', `DPoP ${fixture3.access_token}`)
                .expect(401)
                .expect('WWW-Authenticate', /^DPoP /)
                .expect('WWW-Authenticate', /algs="ES256 PS256"/)
                .expect('WWW-Authenticate', /DPoP proof iat is not recent enough/)
                .expect(({ headers }) => {
                  if (enabled) {
                    ((actual) => { assert.ok('dpop-nonce' in Object(actual)); assert.match(actual['dpop-nonce'], /^[\w-]{43}$/); })(headers);
                    ((actual) => { assert.ok('www-authenticate' in Object(actual)); assert.match(actual['www-authenticate'], /error="use_dpop_nonce"/); })(headers);
                    ((actual) => { assert.ok('www-authenticate' in Object(actual)); assert.match(actual['www-authenticate'], /use a DPoP nonce instead/); })(headers);
                  } else {
                    assert.ok(!('dpop-nonce' in Object(headers)));
                    ((actual) => { assert.ok('www-authenticate' in Object(actual)); assert.match(actual['www-authenticate'], /error="invalid_dpop_proof"/); })(headers);
                  }
                });
            });
          }
        });
      }
    });

    it("doesn't allow Bearer tokens to be passed with DPoP scheme", { timeout: 3000 }, async () => {
      const at = new fixture1.provider.AccessToken({
        accountId: fixture1.loggedInAccountId,
        grantId: fixture1.getGrantId(),
        client: await fixture1.provider.Client.find('client'),
        scope: 'openid',
      });

      const dpop = await at.save();
      const proof = await DPoP(fixture1.keypair, `${fixture1.provider.issuer}${fixture1.suitePath('/me')}`, 'GET', undefined, dpop);
      const spy = sinon.spy();
      fixture1.provider.once('userinfo.error', spy);

      await fixture1.agent.get('/me')
        .set('Authorization', `DPoP ${dpop}`)
        .set('DPoP', proof)
        .expect(fixture1.failWith(401, 'invalid_token', 'invalid token provided', undefined, 'DPoP'));

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
      assert.ok(spy.args[0][1] instanceof InvalidToken);
      ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'access token is not sender-constrained but proof of possession was provided'); })(spy.args[0][1]);
    });

    it('acts like an RS checking the DPoP proof and thumbprint now', { timeout: 3000 }, async () => {
      const at = new fixture1.provider.AccessToken({
        accountId: fixture1.loggedInAccountId,
        grantId: fixture1.getGrantId(),
        client: await fixture1.provider.Client.find('client'),
        scope: 'openid',
      });
      at.setThumbprint('jkt', fixture1.thumbprint);

      const dpop = await at.save();
      const proof = await DPoP(fixture1.keypair, `${fixture1.provider.issuer}${fixture1.suitePath('/me')}`, 'GET', undefined, dpop);

      await fixture1.agent.get('/me')
        .set('Authorization', `DPoP ${dpop}`)
        .set('DPoP', proof)
        .expect(200);

      let spy = sinon.spy();
      fixture1.provider.once('userinfo.error', spy);

      await fixture1.agent.get('/me')
        .set('Authorization', `DPoP ${dpop}`)
        .set('DPoP', proof)
        .expect(401)
        .expect({ error: 'invalid_token', error_description: 'invalid token provided' });

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
      assert.ok(spy.args[0][1] instanceof InvalidToken);
      ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'DPoP proof JWT Replay detected'); })(spy.args[0][1]);

      {
        const token = 'token';
        await fixture1.agent.get('/me')
          .set('Authorization', `DPoP ${token}`)
          .set('DPoP', await DPoP(await generateKeyPair('ES256', { extractable: true }), `${fixture1.provider.issuer}${fixture1.suitePath('/me')}`, 'GET', undefined, token))
          .expect(fixture1.failWith(401, 'invalid_token', 'invalid token provided', undefined, 'DPoP'));
      }

      spy = sinon.spy();
      fixture1.provider.once('userinfo.error', spy);

      await fixture1.agent.get('/me')
        .set('Authorization', `DPoP ${dpop}`)
        .set('DPoP', await DPoP(await generateKeyPair('ES256', { extractable: true }), `${fixture1.provider.issuer}${fixture1.suitePath('/me')}`, 'GET', undefined, dpop))
        .expect(fixture1.failWith(401, 'invalid_token', 'invalid token provided', undefined, 'DPoP'));

      await fixture1.agent.get('/me')
        .set('Authorization', `DPoP ${dpop}`)
        .set('DPoP', await DPoP(fixture1.keypair, `${fixture1.provider.issuer}${fixture1.suitePath('/me')}`, 'GET', undefined, 'anotherAccessTokenValue'))
        .expect({ error: 'invalid_dpop_proof', error_description: 'DPoP proof ath mismatch' })
        .expect(401);

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
      ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'failed jkt verification'); })(spy.args[0][1]);

      spy = sinon.spy();
      fixture1.provider.once('userinfo.error', spy);

      await fixture1.agent.get('/me')
        .set('Authorization', `Bearer ${dpop}`)
        .expect(fixture1.failWith(401, 'invalid_token', 'invalid token provided', undefined, 'DPoP'));

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
      ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'failed jkt verification'); })(spy.args[0][1]);
    });
  });

  describe('introspection', () => {
    const fixture4 = Object.create(fixture);

    it('exposes cnf and DPoP proof JWT type now', { timeout: 3000 }, async () => {
      const at = new fixture4.provider.AccessToken({
        accountId: 'account',
        client: await fixture4.provider.Client.find('client'),
        scope: 'openid',
      });
      at.setThumbprint('jkt', fixture4.thumbprint);

      const token = await at.save();

      await fixture4.agent.post('/token/introspection')
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(200)
        .expect(({ body }) => {
          assert.ok('cnf' in Object(body));
          ((actual) => { assert.ok('token_type' in Object(actual)); assert.equal(actual.token_type, 'DPoP'); })(body);
          assert.ok('jkt' in Object(body.cnf));
        });
    });
  });

  describe('urn:ietf:params:oauth:grant-type:device_code', () => {
    const fixture5 = Object.create(fixture);

    beforeEach(async () => {
      await fixture5.agent.post('/device/auth')
        .auth('client', 'secret')
        .send({ scope: 'openid' })
        .type('form')
        .expect(200)
        .expect(({ body: { device_code: dc } }) => {
          fixture5.dc = dc;
        });

      fixture5.TestAdapter.for('DeviceCode').syncUpdate(fixture5.getTokenJti(fixture5.dc), {
        scope: 'openid offline_access',
        accountId: fixture5.loggedInAccountId,
        grantId: fixture5.getGrantId(),
      });
    }, { timeout: 3000 });

    it('binds the access token to the jwk', { timeout: 3000 }, async () => {
      const spy = sinon.spy();
      fixture5.provider.once('grant.success', spy);

      await fixture5.agent.post('/token')
        .auth('client', 'secret')
        .send({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: fixture5.dc,
        })
        .type('form')
        .set('DPoP', await DPoP(fixture5.keypair, `${fixture5.provider.issuer}${fixture5.suitePath('/token')}`, 'POST'))
        .expect(200);

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
      const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
      ((actual) => { assert.ok('jkt' in Object(actual)); assert.equal(actual.jkt, fixture5.thumbprint); })(AccessToken);
      assert.ok(!('jkt' in Object(RefreshToken)));
    });

    it('binds the refresh token to the jwk for public clients', { timeout: 3000 }, async () => {
      const spy = sinon.spy();
      fixture5.provider.once('grant.success', spy);

      // changes the code to client-none
      fixture5.TestAdapter.for('DeviceCode').syncUpdate(fixture5.getTokenJti(fixture5.dc), {
        clientId: 'client-none',
        accountId: fixture5.loggedInAccountId,
        grantId: fixture5.getGrantId('client-none'),
      });

      await fixture5.agent.post('/token')
        .send({
          client_id: 'client-none',
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: fixture5.dc,
        })
        .type('form')
        .set('DPoP', await DPoP(fixture5.keypair, `${fixture5.provider.issuer}${fixture5.suitePath('/token')}`, 'POST'))
        .expect(200);

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
      const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
      ((actual) => { assert.ok('jkt' in Object(actual)); assert.equal(actual.jkt, fixture5.thumbprint); })(AccessToken);
      ((actual) => { assert.ok('jkt' in Object(actual)); assert.equal(actual.jkt, fixture5.thumbprint); })(RefreshToken);
    });
  });

  describe('urn:openid:params:grant-type:ciba', () => {
    const fixture6 = Object.create(fixture);

    beforeEach(async () => {
      await fixture6.agent.post('/backchannel')
        .auth('client', 'secret')
        .send({
          scope: 'openid offline_access',
          login_hint: 'accountId',
        })
        .type('form')
        .expect(200)
        .expect(({ body: { auth_req_id: reqId } }) => {
          fixture6.reqId = reqId;
        });
    }, { timeout: 3000 });

    it('binds the access token to the jwk', { timeout: 3000 }, async () => {
      const spy = sinon.spy();
      fixture6.provider.once('grant.success', spy);

      await fixture6.agent.post('/token')
        .auth('client', 'secret')
        .send({
          grant_type: 'urn:openid:params:grant-type:ciba',
          auth_req_id: fixture6.reqId,
        })
        .type('form')
        .set('DPoP', await DPoP(fixture6.keypair, `${fixture6.provider.issuer}${fixture6.suitePath('/token')}`, 'POST'))
        .expect(200);

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
      const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
      ((actual) => { assert.ok('jkt' in Object(actual)); assert.equal(actual.jkt, fixture6.thumbprint); })(AccessToken);
      assert.ok(!('jkt' in Object(RefreshToken)));
    });

    it('binds the refresh token to the jwk for public clients', { timeout: 3000 }, async () => {
      const spy = sinon.spy();
      fixture6.provider.once('grant.success', spy);

      // changes the code to client-none
      fixture6.TestAdapter.for('BackchannelAuthenticationRequest').syncUpdate(fixture6.getTokenJti(fixture6.reqId), {
        clientId: 'client-none',
      });
      const { grantId } = fixture6.TestAdapter.for('BackchannelAuthenticationRequest').syncFind(fixture6.getTokenJti(fixture6.reqId));
      fixture6.TestAdapter.for('Grant').syncUpdate(grantId, {
        clientId: 'client-none',
      });

      await fixture6.agent.post('/token')
        .send({
          client_id: 'client-none',
          grant_type: 'urn:openid:params:grant-type:ciba',
          auth_req_id: fixture6.reqId,
        })
        .type('form')
        .set('DPoP', await DPoP(fixture6.keypair, `${fixture6.provider.issuer}${fixture6.suitePath('/token')}`, 'POST'))
        .expect(200);

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
      const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
      ((actual) => { assert.ok('jkt' in Object(actual)); assert.equal(actual.jkt, fixture6.thumbprint); })(AccessToken);
      ((actual) => { assert.ok('jkt' in Object(actual)); assert.equal(actual.jkt, fixture6.thumbprint); })(RefreshToken);
    });
  });

  describe('pushed authorization request', () => {
    const fixture7 = Object.create(fixture);

    it('rejects replayed proofs with an InvalidRequest', { timeout: 3000 }, async () => {
      const proof = await DPoP(
        fixture7.keypair,
        `${fixture7.provider.issuer}${fixture7.suitePath('/request')}`,
        'POST',
      );
      const request = () => fixture7.agent.post('/request')
        .auth('client', 'secret')
        .send({
          response_type: 'code',
          client_id: 'client',
        })
        .set('DPoP', proof)
        .type('form');

      await request().expect(201);

      const spy = sinon.spy();
      fixture7.provider.once('pushed_authorization_request.error', spy);
      await request()
        .expect(400)
        .expect({
          error: 'invalid_request',
          error_description: 'DPoP proof JWT Replay detected',
        });

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
      assert.ok(spy.args[0][1] instanceof InvalidRequest);
    });

    for (const offset of [0, 295, 300, 295.5]) {
      it(`rejects replays throughout the iat window with a ${offset}s clock offset`, { timeout: 3000 }, async () => {
        const now = epochTime();
        const { configuration } = i(fixture7.provider);
        const { clockTolerance } = configuration;
        configuration.clockTolerance = 0;
        timekeeper.freeze(now * 1000);

        try {
          const proof = await DPoP(
            fixture7.keypair,
            `${fixture7.provider.issuer}${fixture7.suitePath('/request')}`,
            'POST',
            undefined,
            undefined,
            now + offset,
          );
          const request = () => fixture7.agent.post('/request')
            .auth('client', 'secret')
            .send({ response_type: 'code', client_id: 'client' })
            .set('DPoP', proof)
            .type('form');
          const replay = () => request().expect(400).expect({
            error: 'invalid_request',
            error_description: 'DPoP proof JWT Replay detected',
          });

          await request().expect(201);
          await replay();

          if (offset > 0) {
            timekeeper.freeze((now + CHALLENGE_OK_WINDOW + 5) * 1000);
            await replay();
          }

          const lastAccepted = Math.floor(now + offset + CHALLENGE_OK_WINDOW);
          timekeeper.freeze(lastAccepted * 1000);
          await replay();

          timekeeper.freeze((lastAccepted + 1) * 1000);
          await request().expect(400).expect({
            error: 'use_dpop_nonce',
            error_description: 'DPoP proof iat is not recent enough, use a DPoP nonce instead',
          });
        } finally {
          configuration.clockTolerance = clockTolerance;
          timekeeper.reset();
        }
      });
    }

    it('checks dpop_jkt equals the jwk thumbprint when both are present', { timeout: 3000 }, async () => {
      await fixture7.agent.post('/request')
        .auth('client', 'secret')
        .send({
          response_type: 'code',
          client_id: 'client',
          dpop_jkt: fixture7.thumbprint,
        })
        .set('DPoP', await DPoP(fixture7.keypair, `${fixture7.provider.issuer}${fixture7.suitePath('/request')}`, 'POST'))
        .type('form')
        .expect(201);

      await fixture7.agent.post('/request')
        .auth('client', 'secret')
        .send({
          response_type: 'code',
          client_id: 'client',
          dpop_jkt: 'cbaZgHZazjgQq0Q2-Hy_o2-OCDpPu02S30lNhTsNU1Q',
        })
        .set('DPoP', await DPoP(fixture7.keypair, `${fixture7.provider.issuer}${fixture7.suitePath('/request')}`, 'POST'))
        .type('form')
        .expect(400)
        .expect({ error: 'invalid_request', error_description: 'DPoP proof key thumbprint does not match dpop_jkt' });
    });

    it('sets the request dpop_jkt automatically when missing (no request object used)', { timeout: 3000 }, async () => {
      let request_uri;
      await fixture7.agent.post('/request')
        .auth('client', 'secret')
        .send({
          scope: 'openid',
          response_type: 'code',
          client_id: 'client',
        })
        .set('DPoP', await DPoP(fixture7.keypair, `${fixture7.provider.issuer}${fixture7.suitePath('/request')}`, 'POST'))
        .type('form')
        .expect(201)
        .expect(({ body }) => {
          ({ request_uri } = body);
        });

      const auth = new fixture7.AuthorizationRequest({
        request_uri,
      });

      let code;
      await fixture7.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validateClientLocation)
        .expect(({ headers: { location } }) => {
          ({ query: { code } } = url.parse(location, true));
        });

      const { dpopJkt } = fixture7.TestAdapter.for('AuthorizationCode').syncFind(code);
      ((actual) => { assert.equal(typeof actual, 'string'); assert.equal(actual.length, 43); })(dpopJkt);
    });

    it('sets the request dpop_jkt automatically when missing (request object used)', { timeout: 3000 }, async () => {
      let request_uri;
      await fixture7.agent.post('/request')
        .auth('client', 'secret')
        .send({
          client_id: 'client',
          request: await new SignJWT({
            client_id: 'client',
            scope: 'openid',
            response_type: 'code',
            iss: 'client',
            aud: fixture7.provider.issuer,
          })
            .setProtectedHeader({ alg: 'HS256' })
            .setIssuedAt()
            .setIssuer('client')
            .setAudience(fixture7.provider.issuer)
            .setExpirationTime('1m')
            .setNotBefore('0s')
            .sign(Buffer.from('secret')),
        })
        .set('DPoP', await DPoP(fixture7.keypair, `${fixture7.provider.issuer}${fixture7.suitePath('/request')}`, 'POST'))
        .type('form')
        .expect(201)
        .expect(({ body }) => {
          ({ request_uri } = body);
        });

      const auth = new fixture7.AuthorizationRequest({
        request_uri,
      });

      let code;
      await fixture7.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validateClientLocation)
        .expect(({ headers: { location } }) => {
          ({ query: { code } } = url.parse(location, true));
        });

      const { dpopJkt } = fixture7.TestAdapter.for('AuthorizationCode').syncFind(code);
      ((actual) => { assert.equal(typeof actual, 'string'); assert.equal(actual.length, 43); })(dpopJkt);
    });
  });

  describe('authorization flow', () => {
    const fixture8 = Object.create(fixture);

    describe('without dpop_jkt', () => {
      const fixture9 = Object.create(fixture8);

      beforeEach(async () => {
        // biome-ignore lint/suspicious/noAssignInExpressions: test pattern
        const auth = fixture9.auth = new fixture9.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid offline_access',
          prompt: 'consent',
        });

        await fixture9.wrap({ route: '/auth', verb: 'get', auth })
          .expect(303)
          .expect(auth.validateClientLocation)
          .expect(({ headers: { location } }) => {
            const { query: { code } } = url.parse(location, true);
            fixture9.code = code;
          });
      }, { timeout: 3000 });

      describe('authorization_code', () => {
        const fixture10 = Object.create(fixture9);

        it('binds the access token to the jwk', { timeout: 3000 }, async () => {
          const spy = sinon.spy();
          fixture10.provider.once('grant.success', spy);

          await fixture10.agent.post('/token')
            .auth('client', 'secret')
            .send({
              grant_type: 'authorization_code',
              code_verifier: fixture10.auth.code_verifier,
              code: fixture10.code,
              redirect_uri: 'https://client.example.com/cb',
            })
            .type('form')
            .set('DPoP', await DPoP(fixture10.keypair, `${fixture10.provider.issuer}${fixture10.suitePath('/token')}`, 'POST'))
            .expect(200);

          ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
          const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
          ((actual) => { assert.ok('jkt' in Object(actual)); assert.equal(actual.jkt, fixture10.thumbprint); })(AccessToken);
          assert.ok(!('jkt' in Object(RefreshToken)));
        });
      });
    });

    describe('with dpop_jkt', () => {
      const fixture11 = Object.create(fixture8);

      beforeEach(async () => {
        // biome-ignore lint/suspicious/noAssignInExpressions: test pattern
        const auth = fixture11.auth = new fixture11.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid offline_access',
          prompt: 'consent',
          dpop_jkt: fixture11.thumbprint,
        });

        await fixture11.wrap({ route: '/auth', verb: 'get', auth })
          .expect(303)
          .expect(auth.validateClientLocation)
          .expect(({ headers: { location } }) => {
            const { query: { code } } = url.parse(location, true);
            fixture11.code = code;
          });
      }, { timeout: 3000 });

      describe('authorization_code', () => {
        const fixture12 = Object.create(fixture11);

        it('binds the access token to the jwk', { timeout: 3000 }, async () => {
          const spy = sinon.spy();
          fixture12.provider.once('grant.success', spy);

          await fixture12.agent.post('/token')
            .auth('client', 'secret')
            .send({
              grant_type: 'authorization_code',
              code_verifier: fixture12.auth.code_verifier,
              code: fixture12.code,
              redirect_uri: 'https://client.example.com/cb',
            })
            .type('form')
            .set('DPoP', await DPoP(fixture12.keypair, `${fixture12.provider.issuer}${fixture12.suitePath('/token')}`, 'POST'))
            .expect(200);

          ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
          const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
          ((actual) => { assert.ok('jkt' in Object(actual)); assert.equal(actual.jkt, fixture12.thumbprint); })(AccessToken);
          assert.ok(!('jkt' in Object(RefreshToken)));
        });

        it('checks the dpop_jkt matches the proof jwk thumbprint', { timeout: 3000 }, async () => {
          const spy = sinon.spy();
          fixture12.provider.once('grant.error', spy);

          await fixture12.agent.post('/token')
            .auth('client', 'secret')
            .send({
              grant_type: 'authorization_code',
              code_verifier: fixture12.auth.code_verifier,
              code: fixture12.code,
              redirect_uri: 'https://client.example.com/cb',
            })
            .type('form')
            .set('DPoP', await DPoP(await generateKeyPair('ES256', { extractable: true }), `${fixture12.provider.issuer}${fixture12.suitePath('/token')}`, 'POST'))
            .expect(400)
            .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

          ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
          ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'DPoP proof key thumbprint does not match dpop_jkt'); })(spy.args[0][1]);
        });

        it('requires dpop to be used when dpop_jkt was present', { timeout: 3000 }, async () => {
          const spy = sinon.spy();
          fixture12.provider.once('grant.error', spy);

          await fixture12.agent.post('/token')
            .auth('client', 'secret')
            .send({
              grant_type: 'authorization_code',
              code_verifier: fixture12.auth.code_verifier,
              code: fixture12.code,
              redirect_uri: 'https://client.example.com/cb',
            })
            .type('form')
            .expect(400)
            .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

          ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
          ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'missing DPoP proof JWT'); })(spy.args[0][1]);
        });
      });
    });

    describe('refresh_token', () => {
      const fixture13 = Object.create(fixture8);

      beforeEach(async () => {
        // biome-ignore lint/suspicious/noAssignInExpressions: test pattern
        const auth = fixture13.auth = new fixture13.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid offline_access',
          prompt: 'consent',
        });

        await fixture13.wrap({ route: '/auth', verb: 'get', auth })
          .expect(303)
          .expect(auth.validateClientLocation)
          .expect(({ headers: { location } }) => {
            const { query: { code } } = url.parse(location, true);
            fixture13.code = code;
          });

        await fixture13.agent.post('/token')
          .auth('client', 'secret')
          .send({
            grant_type: 'authorization_code',
            code_verifier: fixture13.auth.code_verifier,
            code: fixture13.code,
            redirect_uri: 'https://client.example.com/cb',
          })
          .type('form')
          .set('DPoP', await DPoP(fixture13.keypair, `${fixture13.provider.issuer}${fixture13.suitePath('/token')}`, 'POST'))
          .expect(({ body }) => {
            fixture13.rt = body.refresh_token;
          });
      }, { timeout: 3000 });

      it('binds the access token to the jwk', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture13.provider.once('grant.success', spy);

        await fixture13.agent.post('/token')
          .auth('client', 'secret')
          .send({
            grant_type: 'refresh_token',
            refresh_token: fixture13.rt,
          })
          .type('form')
          .set('DPoP', await DPoP(fixture13.keypair, `${fixture13.provider.issuer}${fixture13.suitePath('/token')}`, 'POST'))
          .expect(200);

        ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
        const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
        ((actual) => { assert.ok('jkt' in Object(actual)); assert.equal(actual.jkt, fixture13.thumbprint); })(AccessToken);
        assert.equal(RefreshToken.jkt, undefined);
      });
    });
  });

  describe('authorization flow (public client)', () => {
    const fixture14 = Object.create(fixture);

    beforeEach(async () => {
      // biome-ignore lint/suspicious/noAssignInExpressions: test pattern
      const auth = fixture14.auth = new fixture14.AuthorizationRequest({
        client_id: 'client-none',
        response_type: 'code',
        scope: 'openid offline_access',
        prompt: 'consent',
      });

      await fixture14.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validateClientLocation)
        .expect(({ headers: { location } }) => {
          const { query: { code } } = url.parse(location, true);
          fixture14.code = code;
        });
    }, { timeout: 3000 });

    describe('authorization_code', () => {
      const fixture15 = Object.create(fixture14);

      it('binds the access token to the jwk', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture15.provider.once('grant.success', spy);

        await fixture15.agent.post('/token')
          .send({
            client_id: 'client-none',
            grant_type: 'authorization_code',
            code_verifier: fixture15.auth.code_verifier,
            code: fixture15.code,
            redirect_uri: 'https://client.example.com/cb',
          })
          .type('form')
          .set('DPoP', await DPoP(fixture15.keypair, `${fixture15.provider.issuer}${fixture15.suitePath('/token')}`, 'POST'))
          .expect(200);

        ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
        const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
        ((actual) => { assert.ok('jkt' in Object(actual)); assert.equal(actual.jkt, fixture15.thumbprint); })(AccessToken);
        ((actual) => { assert.ok('jkt' in Object(actual)); assert.equal(actual.jkt, fixture15.thumbprint); })(RefreshToken);
      });
    });

    describe('refresh_token', () => {
      const fixture16 = Object.create(fixture14);

      beforeEach(async () => {
        await fixture16.agent.post('/token')
          .send({
            client_id: 'client-none',
            grant_type: 'authorization_code',
            code_verifier: fixture16.auth.code_verifier,
            code: fixture16.code,
            redirect_uri: 'https://client.example.com/cb',
          })
          .type('form')
          .set('DPoP', await DPoP(fixture16.keypair, `${fixture16.provider.issuer}${fixture16.suitePath('/token')}`, 'POST'))
          .expect(({ body }) => {
            fixture16.rt = body.refresh_token;
          });
      }, { timeout: 3000 });

      it('binds the access token to the jwk', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture16.provider.once('grant.success', spy);

        await fixture16.agent.post('/token')
          .send({
            client_id: 'client-none',
            grant_type: 'refresh_token',
            refresh_token: fixture16.rt,
          })
          .type('form')
          .set('DPoP', await DPoP(fixture16.keypair, `${fixture16.provider.issuer}${fixture16.suitePath('/token')}`, 'POST'))
          .expect(200);

        ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
        const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
        ((actual) => { assert.ok('jkt' in Object(actual)); assert.equal(actual.jkt, fixture16.thumbprint); })(AccessToken);
        ((actual) => { assert.ok('jkt' in Object(actual)); assert.equal(actual.jkt, fixture16.thumbprint); })(RefreshToken);
      });

      it('rejects a future-dated proof replay after the original replay TTL', { timeout: 3000 }, async () => {
        const now = epochTime();
        const { configuration } = i(fixture16.provider);
        const { clockTolerance } = configuration;
        configuration.clockTolerance = 0;
        timekeeper.freeze(now * 1000);

        try {
          const proof = await DPoP(
            fixture16.keypair,
            `${fixture16.provider.issuer}${fixture16.suitePath('/token')}`,
            'POST',
            undefined,
            undefined,
            now + 295,
          );
          const request = () => fixture16.agent.post('/token')
            .send({
              client_id: 'client-none',
              grant_type: 'refresh_token',
              refresh_token: fixture16.rt,
            })
            .set('DPoP', proof)
            .type('form');

          await request().expect(200);

          for (const elapsed of [0, CHALLENGE_OK_WINDOW + 5]) {
            timekeeper.freeze((now + elapsed) * 1000);
            const spy = sinon.spy();
            fixture16.provider.once('grant.error', spy);
            await request().expect(400).expect({
              error: 'invalid_grant',
              error_description: 'grant request is invalid',
            });
            assert.ok(spy.calledOnce);
            assert.ok(spy.firstCall.args[1] instanceof InvalidGrant);
            assert.equal(spy.firstCall.args[1].error_detail, 'DPoP proof JWT Replay detected');
          }
        } finally {
          configuration.clockTolerance = clockTolerance;
          timekeeper.reset();
        }
      });

      it('verifies the request made with the same cert jwk', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture16.provider.once('grant.error', spy);

        await fixture16.agent.post('/token')
          .send({
            client_id: 'client-none',
            grant_type: 'refresh_token',
            refresh_token: fixture16.rt,
          })
          .set('DPoP', await DPoP(await generateKeyPair('ES256', { extractable: true }), `${fixture16.provider.issuer}${fixture16.suitePath('/token')}`, 'POST'))
          .type('form')
          .expect(400)
          .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

        ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
        ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'failed jkt verification'); })(spy.args[0][1]);
      });

      it('rejects a replay before repeating the token binding check', { timeout: 3000 }, async () => {
        const proof = await DPoP(
          await generateKeyPair('ES256', { extractable: true }),
          `${fixture16.provider.issuer}${fixture16.suitePath('/token')}`,
          'POST',
        );
        const errors = [];
        const listener = (_ctx, err) => errors.push(err);
        const request = () => fixture16.agent.post('/token')
          .send({
            client_id: 'client-none',
            grant_type: 'refresh_token',
            refresh_token: fixture16.rt,
          })
          .set('DPoP', proof)
          .type('form')
          .expect(400)
          .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

        fixture16.provider.on('grant.error', listener);
        try {
          await request();
          await request();
        } finally {
          fixture16.provider.removeListener('grant.error', listener);
        }

        assert.equal(errors.length, 2);
        assert.ok(errors[0] instanceof InvalidGrant);
        ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'failed jkt verification'); })(errors[0]);
        assert.ok(errors[1] instanceof InvalidGrant);
        ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'DPoP proof JWT Replay detected'); })(errors[1]);
      });
    });
  });

  describe('client_credentials', () => {
    const fixture17 = Object.create(fixture);

    it('binds the access token to the jwk', { timeout: 3000 }, async () => {
      const spy = sinon.spy();
      fixture17.provider.once('grant.success', spy);

      await fixture17.agent.post('/token')
        .auth('client', 'secret')
        .send({ grant_type: 'client_credentials' })
        .set('DPoP', await DPoP(fixture17.keypair, `${fixture17.provider.issuer}${fixture17.suitePath('/token')}`, 'POST'))
        .type('form')
        .expect(200);

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
      const { oidc: { entities: { ClientCredentials } } } = spy.args[0][0];
      ((actual) => { assert.ok('jkt' in Object(actual)); assert.equal(actual.jkt, fixture17.thumbprint); })(ClientCredentials);
    });

    it('uses the client and proof identifiers with the replay window TTL', { timeout: 3000 }, async () => {
      const proof = await DPoP(
        fixture17.keypair,
        `${fixture17.provider.issuer}${fixture17.suitePath('/token')}`,
        'POST',
      );
      const unique = sinon.spy(fixture17.provider.ReplayDetection, 'unique');

      try {
        const before = epochTime();
        await fixture17.agent.post('/token')
          .auth('client', 'secret')
          .send({ grant_type: 'client_credentials' })
          .set('DPoP', proof)
          .type('form')
          .expect(200);
        const after = epochTime();

        ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(unique);
        assert.equal(unique.firstCall.args[0], 'client');
        assert.equal(unique.firstCall.args[1], decodeJwt(proof).jti);
        const ttl = (2 * CHALLENGE_OK_WINDOW) + 1;
        assert.ok(unique.firstCall.args[2] >= before + ttl);
        assert.ok(unique.firstCall.args[2] <= after + ttl);

        const spy = sinon.spy();
        fixture17.provider.once('grant.error', spy);
        await fixture17.agent.post('/token')
          .auth('client', 'secret')
          .send({ grant_type: 'client_credentials' })
          .set('DPoP', proof)
          .type('form')
          .expect(400)
          .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

        ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
        assert.ok(spy.args[0][1] instanceof InvalidGrant);
        ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'DPoP proof JWT Replay detected'); })(spy.args[0][1]);
      } finally {
        unique.restore();
      }
    });

    it('allows replay when configured', { timeout: 3000 }, async () => {
      const proof = await DPoP(
        fixture17.keypair,
        `${fixture17.provider.issuer}${fixture17.suitePath('/token')}`,
        'POST',
      );
      const { dPoP } = i(fixture17.provider).features;
      const original = dPoP.allowReplay;
      const unique = sinon.spy(fixture17.provider.ReplayDetection, 'unique');
      const request = () => fixture17.agent.post('/token')
        .auth('client', 'secret')
        .send({ grant_type: 'client_credentials' })
        .set('DPoP', proof)
        .type('form')
        .expect(200);

      dPoP.allowReplay = true;
      try {
        await request();
        await request();
        ((actual) => { assert.ok('notCalled' in Object(actual)); assert.equal(actual.notCalled, true); })(unique);
      } finally {
        dPoP.allowReplay = original;
        unique.restore();
      }
    });
  });

  describe('status codes at the token endpoint', () => {
    const fixture18 = Object.create(fixture);

    it('should be 400 for invalid_dpop_proof', { timeout: 3000 }, async () => {
      await fixture18.agent.post('/token')
        .auth('client', 'secret')
        .send({ grant_type: 'client_credentials' })
        .set('DPoP', 'invalid')
        .type('form')
        .expect(400)
        .expect({ error: 'invalid_dpop_proof', error_description: 'invalid DPoP key binding' });
    });

    it('should be 400 for malformed htu', { timeout: 3000 }, async () => {
      await fixture18.agent.post('/token')
        .auth('client', 'secret')
        .send({ grant_type: 'client_credentials' })
        .set('DPoP', await DPoP(fixture18.keypair, 'not a url', 'POST'))
        .type('form')
        .expect(400)
        .expect({ error: 'invalid_dpop_proof', error_description: 'DPoP proof htu mismatch' });
    });

    it('rejects an htu claim that is not a string', { timeout: 3000 }, async () => {
      await fixture18.agent.post('/token')
        .auth('client', 'secret')
        .send({ grant_type: 'client_credentials' })
        .set('DPoP', await DPoP(
          fixture18.keypair,
          [`${fixture18.provider.issuer}${fixture18.suitePath('/token')}`],
          'POST',
        ))
        .type('form')
        .expect(400)
        .expect({ error: 'invalid_dpop_proof', error_description: 'DPoP proof htu mismatch' });
    });
  });

  describe('invalid nonce', () => {
    const fixture19 = Object.create(fixture);

    it('@ userinfo', { timeout: 3000 }, async () => {
      let nonce;
      await fixture19.agent.get('/me')
        .set('Authorization', 'DPoP foo')
        .set('DPoP', await DPoP(fixture19.keypair, `${fixture19.provider.issuer}${fixture19.suitePath('/me')}`, 'GET', 'foo', 'foo'))
        .expect(401)
        .expect({ error: 'use_dpop_nonce', error_description: 'invalid nonce in DPoP proof' })
        .expect(({ headers }) => { nonce = headers['dpop-nonce']; });

      await fixture19.agent.get('/me')
        .set('Authorization', 'DPoP foo')
        .set('DPoP', await DPoP(fixture19.keypair, `${fixture19.provider.issuer}${fixture19.suitePath('/me')}`, 'GET', nonce, 'foo'))
        .expect(401)
        .expect({ error: 'invalid_token', error_description: 'invalid token provided' });
    });

    it('@ token endpoint', { timeout: 3000 }, async () => {
      let nonce;
      await fixture19.agent.post('/token')
        .auth('client', 'secret')
        .send({ grant_type: 'client_credentials' })
        .set('DPoP', await DPoP(fixture19.keypair, `${fixture19.provider.issuer}${fixture19.suitePath('/token')}`, 'POST', 'foo'))
        .type('form')
        .expect(400)
        .expect({ error: 'use_dpop_nonce', error_description: 'invalid nonce in DPoP proof' })
        .expect(({ headers }) => { nonce = headers['dpop-nonce']; });

      await fixture19.agent.post('/token')
        .auth('client', 'secret')
        .send({ grant_type: 'client_credentials' })
        .set('DPoP', await DPoP(fixture19.keypair, `${fixture19.provider.issuer}${fixture19.suitePath('/token')}`, 'POST', nonce))
        .type('form')
        .expect(200);
    });
  });

  describe('required nonce', () => {
    const fixture20 = Object.create(fixture);

    before(() => {
      fixture20.orig = i(fixture20.provider).features.dPoP.requireNonce;
      i(fixture20.provider).features.dPoP.requireNonce = () => true;
    }, { timeout: 3000 });

    after(() => {
      i(fixture20.provider).features.dPoP.requireNonce = fixture20.orig;
    }, { timeout: 3000 });

    it('@ PAR endpoint', { timeout: 3000 }, async () => {
      let nonce;
      await fixture20.agent.post('/request')
        .auth('client', 'secret')
        .send({
          response_type: 'code',
          client_id: 'client',
        })
        .set('DPoP', await DPoP(fixture20.keypair, `${fixture20.provider.issuer}${fixture20.suitePath('/request')}`, 'POST'))
        .type('form')
        .expect(400)
        .expect('DPoP-Nonce', /^[\w-]{43}$/)
        .expect({ error: 'use_dpop_nonce', error_description: 'nonce is required in the DPoP proof' })
        .expect(({ headers }) => { nonce = headers['dpop-nonce']; });

      await fixture20.agent.post('/request')
        .auth('client', 'secret')
        .send({
          response_type: 'code',
          client_id: 'client',
        })
        .set('DPoP', await DPoP(fixture20.keypair, `${fixture20.provider.issuer}${fixture20.suitePath('/request')}`, 'POST', nonce))
        .type('form')
        .expect(201)
        .expect((response) => {
          // because the sent one is fresh
          assert.ok(!('dpop-nonce' in Object(response.headers)));
        });
    });

    it('@ userinfo', { timeout: 3000 }, async () => {
      let nonce;
      await fixture20.agent.get('/me')
        .set('Authorization', 'DPoP foo')
        .set('DPoP', await DPoP(fixture20.keypair, `${fixture20.provider.issuer}${fixture20.suitePath('/me')}`, 'GET', undefined, 'foo'))
        .expect(401)
        .expect({ error: 'use_dpop_nonce', error_description: 'nonce is required in the DPoP proof' })
        .expect(({ headers }) => { nonce = headers['dpop-nonce']; });

      await fixture20.agent.get('/me')
        .set('Authorization', 'DPoP foo')
        .set('DPoP', await DPoP(fixture20.keypair, `${fixture20.provider.issuer}${fixture20.suitePath('/me')}`, 'GET', nonce, 'foo'))
        .expect(401)
        .expect((response) => {
          // because the sent one is fresh
          assert.ok(!('dpop-nonce' in Object(response.headers)));
        })
        .expect({ error: 'invalid_token', error_description: 'invalid token provided' });
    });

    it('@ token endpoint', { timeout: 3000 }, async () => {
      let nonce;
      await fixture20.agent.post('/token')
        .auth('client', 'secret')
        .send({ grant_type: 'client_credentials' })
        .set('DPoP', await DPoP(fixture20.keypair, `${fixture20.provider.issuer}${fixture20.suitePath('/token')}`, 'POST'))
        .type('form')
        .expect(400)
        .expect({ error: 'use_dpop_nonce', error_description: 'nonce is required in the DPoP proof' })
        .expect(({ headers }) => { nonce = headers['dpop-nonce']; });

      await fixture20.agent.post('/token')
        .auth('client', 'secret')
        .send({ grant_type: 'client_credentials' })
        .set('DPoP', await DPoP(fixture20.keypair, `${fixture20.provider.issuer}${fixture20.suitePath('/token')}`, 'POST', nonce))
        .type('form')
        .expect(200)
        .expect((response) => {
          // because the sent one is fresh
          assert.ok(!('dpop-nonce' in Object(response.headers)));
        });
    });
  });
});
