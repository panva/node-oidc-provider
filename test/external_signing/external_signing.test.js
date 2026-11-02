import { describe, before, after, it } from 'node:test';
import assert from 'node:assert/strict';
import * as url from 'node:url';

import * as jose from 'jose';

import bootstrap, { enableNetConnect, resetNetConnect } from '../test_helper.js';

import { asyncExternalKey } from './external_signing.config.js';

const route = '/auth';
const response_type = 'id_token';
const scope = 'openid';

describe('External Signing Keys', () => {
  const fixture = {};

  before(() => enableNetConnect(), { timeout: 3000 });
  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });
  before(() => fixture.login(), { timeout: 3000 });
  after(() => resetNetConnect(), { timeout: 3000 });

  it('still signs with in-process JWKS', { timeout: 3000 }, () => {
    const auth = new fixture.AuthorizationRequest({
      client_id: 'client-sig-internal',
      response_type,
      scope,
    });

    return fixture.wrap({ route, verb: 'get', auth })
      .expect(303)
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['id_token', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation);
  });

  it('publishes external signing metadata through discovery', { timeout: 3000 }, () => fixture.agent.get('/.well-known/openid-configuration')
      .expect('Content-Type', /application\/json/)
      .expect(200)
      .expect(({ body }) => {
        assert.ok(body.id_token_signing_alg_values_supported.includes('ES384'));
        assert.equal(body.jwks_uri, fixture.provider.issuer + fixture.suitePath('/jwks'));
        assert.equal(asyncExternalKey.keyObjectCalls, 0);
      }));

  it('but signs with external keys too and verifies them local', { timeout: 3000 }, async () => {
    const auth = new fixture.AuthorizationRequest({
      client_id: 'client-sig-external',
      response_type,
      scope,
    });

    let id_token;
    await fixture.wrap({ route, verb: 'get', auth })
      .expect(303)
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['id_token', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect((response) => {
        ({ query: { id_token } } = url.parse(response.headers.location.replace('#', '?'), true));
      });

    await jose.compactVerify(id_token, jose.createRemoteJWKSet(new URL(fixture.provider.issuer + fixture.suitePath('/jwks'))));

    auth.id_token_hint = id_token;
    await fixture.wrap({ route, verb: 'get', auth })
      .expect(303)
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['id_token', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect((response) => {
        ({ query: { id_token } } = url.parse(response.headers.location.replace('#', '?'), true));
      });
  });

  it('awaits an asynchronous keyObject when verifying locally', { timeout: 3000 }, async () => {
    const auth = new fixture.AuthorizationRequest({
      client_id: 'client-sig-external-async',
      response_type,
      scope,
    });

    let id_token;
    await fixture.wrap({ route, verb: 'get', auth })
      .expect(303)
      .expect((response) => {
        ({ query: { id_token } } = url.parse(response.headers.location.replace('#', '?'), true));
      });

    const calls = asyncExternalKey.keyObjectCalls;

    auth.id_token_hint = id_token;
    await fixture.wrap({ route, verb: 'get', auth })
      .expect(303)
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['id_token', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect((response) => {
        ({ query: { id_token } } = url.parse(response.headers.location.replace('#', '?'), true));
      });

    assert.equal(asyncExternalKey.keyObjectCalls, calls + 1);
  });
});
