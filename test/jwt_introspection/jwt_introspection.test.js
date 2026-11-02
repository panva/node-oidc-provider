import { describe, before, afterEach, it } from 'node:test';
import assert from 'node:assert/strict';
import timekeeper from 'timekeeper';

import bootstrap from '../test_helper.js';
import * as JWT from '../../lib/helpers/jwt.js';
import Provider from '../../lib/index.js';

const route = '/token/introspection';

describe('jwtIntrospection features', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  afterEach(() => timekeeper.reset(), { timeout: 3000 });

  describe('enriched discovery', () => {
    const fixture1 = Object.create(fixture);

    it('shows the url now', { timeout: 3000 }, () => fixture1.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect((response) => {
          assert.ok('introspection_signing_alg_values_supported' in Object(response.body));
        }));
  });

  describe('JWT Response for OAuth Token Introspection', () => {
    const fixture2 = Object.create(fixture);

    before(() => fixture2.login({ accountId: 'accountId' }), { timeout: 3000 });
    it('can only be enabled with introspection', { timeout: 3000 }, () => {
      assert.throws(() => {
        new Provider('http://localhost', {
          features: {
            jwtIntrospection: { enabled: true },
          },
        });
      }, (error) => { assert.ok(error.message.includes('jwtIntrospection is only available in conjunction with introspection')); return true; });
    });

    it('returns the response as json when not negotiated to be a JWT', { timeout: 3000 }, async () => {
      const now = Date.now();
      timekeeper.freeze(now);
      const at = new fixture2.provider.AccessToken({
        accountId: 'accountId',
        grantId: fixture2.getGrantId(),
        client: await fixture2.provider.Client.find('client-signed'),
        scope: 'openid',
      });

      let json;
      let iat;
      const token = await at.save();
      await fixture2.agent.post(route)
        .auth('client-signed', 'secret')
        .send({
          token,
        })
        .type('form')
        .expect(200)
        .expect('content-type', 'application/json; charset=utf-8')
        .expect(({ body }) => {
          json = body;
          iat = json.iat;
        });

      timekeeper.travel(now + (10 * 1000));

      return fixture2.agent.post(route)
        .auth('client-signed', 'secret')
        .send({
          token,
        })
        .type('form')
        .accept('application/token-introspection+jwt')
        .expect(200)
        .expect('content-type', 'application/token-introspection+jwt; charset=utf-8')
        .expect(({ text }) => {
          const {
            payload: {
              iat: jwtIat, iss, aud, token_introspection,
            }, header,
          } = JWT.decode(text);
          assert.deepEqual(iss, fixture2.provider.issuer);
          assert.deepEqual(aud, 'client-signed');
          assert.deepEqual(token_introspection, json);
          assert.deepEqual(jwtIat, iat + 10);
          ((actual) => { assert.ok('typ' in Object(actual)); assert.equal(actual.typ, 'token-introspection+jwt'); })(header);
        });
    });

    it('returns the response as jwt (active: false)', { timeout: 3000 }, async () => {
      const now = Date.now();
      timekeeper.freeze(now);

      return fixture2.agent.post(route)
        .auth('client-signed', 'secret')
        .send({
          token: 'foobar',
        })
        .type('form')
        .accept('application/token-introspection+jwt')
        .expect(200)
        .expect('content-type', 'application/token-introspection+jwt; charset=utf-8')
        .expect(({ text }) => {
          const {
            payload: {
              iat: jwtIat, iss, aud, token_introspection,
            }, header,
          } = JWT.decode(text);
          assert.deepEqual(iss, fixture2.provider.issuer);
          assert.deepEqual(aud, 'client-signed');
          assert.deepEqual(token_introspection, { active: false });
          assert.deepEqual(jwtIat, Math.floor(now / 1000));
          ((actual) => { assert.ok('typ' in Object(actual)); assert.equal(actual.typ, 'token-introspection+jwt'); })(header);
        });
    });

    it('errors when secret is expired for HMAC alg', { timeout: 3000 }, async () => {
      const at = new fixture2.provider.AccessToken({
        accountId: 'accountId',
        grantId: fixture2.getGrantId(),
        client: await fixture2.provider.Client.find('client-HS-expired'),
        scope: 'openid',
      });

      const token = await at.save();

      return fixture2.agent.post(route)
        .send({
          client_id: 'client-HS-expired',
          token,
        })
        .type('form')
        .accept('application/token-introspection+jwt')
        .expect(400)
        .expect('content-type', 'application/json; charset=utf-8')
        .expect({
          error: 'invalid_client',
          error_description: 'client secret is expired - cannot respond with HS256 JWT Introspection response',
        });
    });

    it('non-authenticated without accept: application/token-introspection+jwt fails', { timeout: 3000 }, async () => {
      const at = new fixture2.provider.AccessToken({
        accountId: 'accountId',
        grantId: fixture2.getGrantId(),
        client: await fixture2.provider.Client.find('client-encrypted'),
        scope: 'openid',
      });

      const token = await at.save();
      await fixture2.agent.post(route)
        .send({
          client_id: 'client-encrypted',
          token,
        })
        .type('form')
        .expect(400)
        .expect('content-type', 'application/json; charset=utf-8')
        .expect({
          error: 'invalid_request',
          error_description: 'introspection must be requested with Accept: application/token-introspection+jwt for this client',
        });

      return fixture2.agent.post(route)
        .send({
          client_id: 'client-encrypted',
          token,
        })
        .type('form')
        .accept('application/token-introspection+jwt')
        .expect(200)
        .expect('content-type', 'application/token-introspection+jwt; charset=utf-8')
        .expect(({ text }) => {
          const header = JWT.header(text);
          ((actual) => { assert.ok('alg' in Object(actual)); assert.equal(actual.alg, 'A128KW'); })(header);
          ((actual) => { assert.ok('enc' in Object(actual)); assert.equal(actual.enc, 'A128CBC-HS256'); })(header);
        });
    });
  });
});
