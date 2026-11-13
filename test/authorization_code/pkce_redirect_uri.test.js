import { describe, before, beforeEach, afterEach, it } from 'node:test';
import assert from 'node:assert/strict';

import sinon from 'sinon';

import bootstrap, { passInteractionChecks } from '../test_helper.js';

describe('PKCE authorization code redirect_uri omission', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture, { config: 'pkce_redirect_uri' }), { timeout: 3000 });
  beforeEach(() => fixture.login(), { timeout: 3000 });
  afterEach(() => fixture.logout(), { timeout: 3000 });
  afterEach(() => sinon.restore(), { timeout: 3000 });

  async function authorize(parameters = {}) {
    const auth = new fixture.AuthorizationRequest({
      response_type: 'code',
      scope: 'openid',
      ...parameters,
    });

    await fixture.agent.get('/auth')
      .query(auth)
      .expect(303)
      .expect(auth.validatePresence(['code', 'state']));

    return { auth, code: auth.res.code };
  }

  function exchange({ auth, code }, parameters = {}) {
    const request = fixture.agent.post('/token').type('form');
    const body = {
      grant_type: 'authorization_code',
      code,
      code_verifier: auth.code_verifier,
      ...parameters,
    };

    if (auth.client_id === 'native') {
      body.client_id = 'native';
    } else {
      request.auth(auth.client_id, 'secret');
    }

    return request.send(body);
  }

  function noPkce(client_id = 'client') {
    return authorize({ client_id, code_challenge: undefined, code_challenge_method: undefined });
  }

  it('accepts omission with validated S256 PKCE and multiple registered URIs by default', { timeout: 3000 }, async () => {
    const issued = await authorize();

    await exchange(issued)
      .expect(200)
      .expect(({ body }) => assert.equal(typeof body.access_token, 'string'));
  });

  it('accepts an explicitly supplied matching redirect_uri with S256 PKCE', { timeout: 3000 }, async () => {
    const issued = await authorize();

    await exchange(issued, { redirect_uri: issued.auth.redirect_uri }).expect(200);
  });

  it('rejects an explicitly supplied mismatched redirect_uri even when it is registered', { timeout: 3000 }, async () => {
    const issued = await authorize();

    await exchange(issued, { redirect_uri: 'https://client.example.com/other' })
      .expect(400)
      .expect(({ body }) => assert.equal(body.error, 'invalid_grant'));

    assert.equal(fixture.TestAdapter.for('AuthorizationCode').syncFind(issued.code).consumed, undefined);
  });

  for (const verifier of [undefined, 'incorrect'.repeat(8)]) {
    it(`requires a valid code_verifier when redirect_uri is omitted (${verifier === undefined ? 'missing' : 'incorrect'})`, { timeout: 3000 }, async () => {
      const issued = await authorize();

      await exchange(issued, { code_verifier: verifier })
        .expect(400)
        .expect(({ body }) => assert.equal(body.error, 'invalid_grant'));

      assert.equal(fixture.TestAdapter.for('AuthorizationCode').syncFind(issued.code).consumed, undefined);
    });
  }

  it('does not permit omission merely because the stored challenge method is S256', { timeout: 3000 }, async () => {
    const issued = await authorize();
    fixture.TestAdapter.for('AuthorizationCode').syncUpdate(issued.code, { codeChallenge: undefined });

    await exchange(issued, { code_verifier: undefined })
      .expect(400)
      .expect(({ body }) => {
        assert.equal(body.error, 'invalid_request');
        assert.equal(body.error_description, "missing required parameter 'redirect_uri'");
      });
  });

  it('does not accept a stored challenge with no transformation method', { timeout: 3000 }, async () => {
    const issued = await authorize();
    fixture.TestAdapter.for('AuthorizationCode').syncUpdate(issued.code, { codeChallengeMethod: undefined });

    await exchange(issued)
      .expect(400)
      .expect(({ body }) => assert.equal(body.error, 'invalid_grant'));
  });

  it('does not enable omission with an unsolicited verifier on a code issued without PKCE', { timeout: 3000 }, async () => {
    const issued = await noPkce();

    await exchange(issued)
      .expect(400)
      .expect(({ body }) => assert.equal(body.error, 'invalid_request'));
  });

  it('preserves redirect_uri requirements for codes issued without PKCE', { timeout: 3000 }, async () => {
    const issued = await noPkce();

    await exchange(issued, { code_verifier: undefined })
      .expect(400)
      .expect(({ body }) => {
        assert.equal(body.error, 'invalid_request');
        assert.equal(body.error_description, "missing required parameter 'redirect_uri'");
      });

    await exchange(issued, { code_verifier: undefined, redirect_uri: issued.auth.redirect_uri }).expect(200);
  });

  it('preserves the disabled single registered URI exception without PKCE', { timeout: 3000 }, async () => {
    const issued = await noPkce('single');

    await exchange(issued, { code_verifier: undefined })
      .expect(400)
      .expect(({ body }) => assert.equal(body.error, 'invalid_request'));
  });

  it('preserves the enabled single registered URI exception without PKCE', { timeout: 3000 }, async () => {
    sinon.stub(i(fixture.provider).configuration, 'allowOmittingSingleRegisteredRedirectUri').value(true);
    const issued = await noPkce('single');

    await exchange(issued, { code_verifier: undefined }).expect(200);
  });

  it('does not extend the legacy single registered URI exception to multiple URIs', { timeout: 3000 }, async () => {
    sinon.stub(i(fixture.provider).configuration, 'allowOmittingSingleRegisteredRedirectUri').value(true);
    const issued = await noPkce();

    await exchange(issued, { code_verifier: undefined })
      .expect(400)
      .expect(({ body }) => assert.equal(body.error, 'invalid_request'));
  });

  passInteractionChecks(fixture, 'native_client_prompt', () => {
    it('does not replace an omitted URI with a different registered loopback port before checking PKCE', { timeout: 3000 }, async () => {
      sinon.stub(i(fixture.provider).configuration, 'allowOmittingSingleRegisteredRedirectUri').value(true);
      const issued = await authorize({ client_id: 'native', redirect_uri: 'http://127.0.0.1:49152/cb' });

      await exchange(issued).expect(200);
    });
  });
});
