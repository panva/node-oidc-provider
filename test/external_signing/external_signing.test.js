import * as url from 'node:url';

import * as jose from 'jose';
import { expect } from 'chai';

import bootstrap, { enableNetConnect, resetNetConnect } from '../test_helper.js';

import { asyncExternalKey } from './external_signing.config.js';

const route = '/auth';
const response_type = 'id_token';
const scope = 'openid';

describe('External Signing Keys', () => {
  before(enableNetConnect);
  before(bootstrap(import.meta.url));
  before(function () { return this.login(); });
  after(resetNetConnect);

  it('still signs with in-process JWKS', function () {
    const auth = new this.AuthorizationRequest({
      client_id: 'client-sig-internal',
      response_type,
      scope,
    });

    return this.wrap({ route, verb: 'get', auth })
      .expect(303)
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['id_token', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation);
  });

  it('publishes external signing metadata through discovery', function () {
    return this.agent.get('/.well-known/openid-configuration')
      .expect('Content-Type', /application\/json/)
      .expect(200)
      .expect(({ body }) => {
        expect(body.id_token_signing_alg_values_supported).to.include('ES384');
        expect(body.jwks_uri).to.equal(this.provider.issuer + this.suitePath('/jwks'));
        expect(asyncExternalKey.keyObjectCalls).to.equal(0);
      });
  });

  it('but signs with external keys too and verifies them local', async function () {
    const auth = new this.AuthorizationRequest({
      client_id: 'client-sig-external',
      response_type,
      scope,
    });

    let id_token;
    await this.wrap({ route, verb: 'get', auth })
      .expect(303)
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['id_token', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect((response) => {
        ({ query: { id_token } } = url.parse(response.headers.location.replace('#', '?'), true));
      });

    await jose.compactVerify(id_token, jose.createRemoteJWKSet(new URL(this.provider.issuer + this.suitePath('/jwks'))));

    auth.id_token_hint = id_token;
    await this.wrap({ route, verb: 'get', auth })
      .expect(303)
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['id_token', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect((response) => {
        ({ query: { id_token } } = url.parse(response.headers.location.replace('#', '?'), true));
      });
  });

  it('awaits an asynchronous keyObject when verifying locally', async function () {
    const auth = new this.AuthorizationRequest({
      client_id: 'client-sig-external-async',
      response_type,
      scope,
    });

    let id_token;
    await this.wrap({ route, verb: 'get', auth })
      .expect(303)
      .expect((response) => {
        ({ query: { id_token } } = url.parse(response.headers.location.replace('#', '?'), true));
      });

    const calls = asyncExternalKey.keyObjectCalls;

    auth.id_token_hint = id_token;
    await this.wrap({ route, verb: 'get', auth })
      .expect(303)
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['id_token', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect((response) => {
        ({ query: { id_token } } = url.parse(response.headers.location.replace('#', '?'), true));
      });

    expect(asyncExternalKey.keyObjectCalls).to.equal(calls + 1);
  });
});
