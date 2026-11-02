import { describe, before, beforeEach, after, it } from 'node:test';
import assert from 'node:assert/strict';
import * as url from 'node:url';


import bootstrap, { skipConsent } from '../test_helper.js';

function assignAuthorizationResponseValues({ headers: { location } }) {
  const { query: { access_token, code } } = url.parse(location, true);

  this.access_token = access_token;
  this.code = code;
}

function assignTokenResponseValues({ body }) {
  this.access_token = body.access_token;
  this.refresh_token = body.refresh_token;
}

describe('session bound tokens behaviours', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });
  skipConsent(fixture);

  beforeEach(() => fixture.login({ scope: 'openid offline_access' }), { timeout: 3000 });
  after(() => fixture.logout(), { timeout: 3000 });

  describe('authorization_code flow', () => {
    const fixture1 = Object.create(fixture);

    it('"code" issues tokens bound to session', { timeout: 3000 }, async () => {
      // biome-ignore lint/suspicious/noAssignInExpressions: test pattern
      const auth = fixture1.auth = new fixture1.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      await fixture1.agent.get('/auth')
        .query(auth)
        .expect(303)
        .expect(auth.validatePresence(['code', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(assignAuthorizationResponseValues.bind(fixture1));

      const code = await fixture1.provider.AuthorizationCode.find(fixture1.code);
      ((actual) => { assert.ok('expiresWithSession' in Object(actual)); assert.equal(actual.expiresWithSession, true); })(code);

      await fixture1.agent.post('/token')
        .send({
          client_id: 'client',
          code: fixture1.code,
          grant_type: 'authorization_code',
          code_verifier: fixture1.auth.code_verifier,
        })
        .type('form')
        .expect(200)
        .expect(assignTokenResponseValues.bind(fixture1));

      const token = await fixture1.provider.AccessToken.find(fixture1.access_token);
      ((actual) => { assert.ok('expiresWithSession' in Object(actual)); assert.equal(actual.expiresWithSession, true); })(token);

      await fixture1.agent.get('/me')
        .auth(fixture1.access_token, { type: 'bearer' })
        .expect(200);

      await fixture1.TestAdapter.for('Session').destroy(fixture1.getSessionId());

      await fixture1.agent.get('/me')
        .auth(fixture1.access_token, { type: 'bearer' })
        .expect(401);
    });

    it('"code" with "online" refresh token', { timeout: 3000 }, async () => {
      // biome-ignore lint/suspicious/noAssignInExpressions: test pattern
      const auth = fixture1.auth = new fixture1.AuthorizationRequest({
        client_id: 'client-refresh',
        response_type: 'code',
        scope: 'openid',
      });

      await fixture1.agent.get('/auth')
        .query(auth)
        .expect(303)
        .expect(auth.validatePresence(['code', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(assignAuthorizationResponseValues.bind(fixture1));

      const code = await fixture1.provider.AuthorizationCode.find(fixture1.code);
      ((actual) => { assert.ok('expiresWithSession' in Object(actual)); assert.equal(actual.expiresWithSession, true); })(code);

      await fixture1.agent.post('/token')
        .send({
          client_id: 'client-refresh',
          code: fixture1.code,
          grant_type: 'authorization_code',
          code_verifier: fixture1.auth.code_verifier,
        })
        .type('form')
        .expect(200)
        .expect(assignTokenResponseValues.bind(fixture1));

      let refresh = await fixture1.provider.RefreshToken.find(fixture1.refresh_token);
      ((actual) => { assert.ok('expiresWithSession' in Object(actual)); assert.equal(actual.expiresWithSession, true); })(refresh);

      const token = await fixture1.provider.AccessToken.find(fixture1.access_token);
      ((actual) => { assert.ok('expiresWithSession' in Object(actual)); assert.equal(actual.expiresWithSession, true); })(token);
      await fixture1.agent.get('/me')
        .auth(fixture1.access_token, { type: 'bearer' })
        .expect(200);

      await fixture1.agent.post('/token')
        .send({
          client_id: 'client-refresh',
          refresh_token: fixture1.refresh_token,
          grant_type: 'refresh_token',
        })
        .type('form')
        .expect(200)
        .expect(assignTokenResponseValues.bind(fixture1));

      refresh = await fixture1.provider.RefreshToken.find(fixture1.refresh_token);
      ((actual) => { assert.ok('expiresWithSession' in Object(actual)); assert.equal(actual.expiresWithSession, true); })(refresh);

      {
        const token = await fixture1.provider.AccessToken.find(fixture1.access_token);
        ((actual) => { assert.ok('expiresWithSession' in Object(actual)); assert.equal(actual.expiresWithSession, true); })(token);
      }

      await fixture1.TestAdapter.for('Session').destroy(fixture1.getSessionId());

      await fixture1.agent.get('/me')
        .auth(fixture1.access_token, { type: 'bearer' })
        .expect(401);

      await fixture1.agent.post('/token')
        .send({
          client_id: 'client-refresh',
          refresh_token: fixture1.refresh_token,
          grant_type: 'refresh_token',
        })
        .type('form')
        .expect(400)
        .expect(assignTokenResponseValues.bind(fixture1));
    });

    it('"code" with offline_access refresh token isnt affected', { timeout: 3000 }, async () => {
      // biome-ignore lint/suspicious/noAssignInExpressions: test pattern
      const auth = fixture1.auth = new fixture1.AuthorizationRequest({
        client_id: 'client-offline',
        response_type: 'code',
        scope: 'openid offline_access',
        prompt: 'consent',
      });

      await fixture1.agent.get('/auth')
        .query(auth)
        .expect(303)
        .expect(auth.validatePresence(['code', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(assignAuthorizationResponseValues.bind(fixture1));

      const code = await fixture1.provider.AuthorizationCode.find(fixture1.code);
      assert.ok(!('expiresWithSession' in Object(code)));

      await fixture1.agent.post('/token')
        .send({
          client_id: 'client-offline',
          code: fixture1.code,
          grant_type: 'authorization_code',
          code_verifier: fixture1.auth.code_verifier,
        })
        .type('form')
        .expect(200)
        .expect(assignTokenResponseValues.bind(fixture1));

      let refresh = await fixture1.provider.RefreshToken.find(fixture1.refresh_token);
      assert.ok(!('expiresWithSession' in Object(refresh)));

      {
        const token = await fixture1.provider.AccessToken.find(fixture1.access_token);
        assert.ok(!('expiresWithSession' in Object(token)));
      }

      await fixture1.agent.get('/me')
        .auth(fixture1.access_token, { type: 'bearer' })
        .expect(200);

      await fixture1.agent.post('/token')
        .send({
          client_id: 'client-offline',
          refresh_token: fixture1.refresh_token,
          grant_type: 'refresh_token',
        })
        .type('form')
        .expect(200)
        .expect(assignTokenResponseValues.bind(fixture1));

      const token = await fixture1.provider.AccessToken.find(fixture1.access_token);
      assert.ok(!('expiresWithSession' in Object(token)));
      refresh = await fixture1.provider.RefreshToken.find(fixture1.refresh_token);
      assert.ok(!('expiresWithSession' in Object(refresh)));

      await fixture1.TestAdapter.for('Session').destroy(fixture1.getSessionId());

      await fixture1.agent.get('/me')
        .auth(fixture1.access_token, { type: 'bearer' })
        .expect(200);

      await fixture1.agent.post('/token')
        .send({
          client_id: 'client-offline',
          refresh_token: fixture1.refresh_token,
          grant_type: 'refresh_token',
        })
        .type('form')
        .expect(200)
        .expect(assignTokenResponseValues.bind(fixture1));

      {
        const token = await fixture1.provider.AccessToken.find(fixture1.access_token);
        assert.ok(!('expiresWithSession' in Object(token)));
      }

      refresh = await fixture1.provider.RefreshToken.find(fixture1.refresh_token);
      assert.ok(!('expiresWithSession' in Object(refresh)));
    });
  });

  describe('implicit', () => {
    const fixture2 = Object.create(fixture);

    it('"id_token token" issues token bound to session', { timeout: 3000 }, async () => {
      const auth = new fixture2.AuthorizationRequest({
        response_type: 'id_token token',
        scope: 'openid',
      });

      await fixture2.agent.get('/auth')
        .query(auth)
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['id_token', 'state', 'access_token', 'expires_in', 'token_type', 'scope']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(assignAuthorizationResponseValues.bind(fixture2));

      const token = await fixture2.provider.AccessToken.find(fixture2.access_token);
      ((actual) => { assert.ok('expiresWithSession' in Object(actual)); assert.equal(actual.expiresWithSession, true); })(token);

      await fixture2.agent.get('/me')
        .auth(fixture2.access_token, { type: 'bearer' })
        .expect(200);

      await fixture2.TestAdapter.for('Session').destroy(fixture2.getSessionId());

      await fixture2.agent.get('/me')
        .auth(fixture2.access_token, { type: 'bearer' })
        .expect(401);
    });
  });
});
