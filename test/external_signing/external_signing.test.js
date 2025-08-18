import * as url from 'node:url';

import * as jose from 'jose';

import bootstrap, { enableNetConnect, resetNetConnect } from '../test_helper.js';

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
});
