import { describe, before, it } from 'node:test';
import assert from 'node:assert/strict';

import bootstrap from '../test_helper.js';

describe('registration management with client_id as URI', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  it('returns client_id as a URI string', { timeout: 3000 }, async () => {
    let client_id;
    let registration_client_uri;
    let registration_access_token;

    await fixture.agent.post('/reg')
      .send({
        redirect_uris: ['https://client.example.com/cb'],
      })
      .expect(201)
      .expect((response) => {
        ({ client_id, registration_access_token, registration_client_uri } = response.body);

        const parsed = new URL(registration_client_uri);
        assert.equal(parsed.search.length, 0);
        const i = parsed.pathname.indexOf('/reg/');
        assert.equal(parsed.pathname.slice(i + 5), encodeURIComponent(client_id));
      });

    await fixture.agent.get(new URL(registration_client_uri).pathname)
      .auth(registration_access_token, { type: 'bearer' })
      .expect(200)
      .expect((response) => {
        ({ registration_access_token, registration_client_uri } = response.body);

        const parsed = new URL(registration_client_uri);
        assert.equal(parsed.search.length, 0);
        const i = parsed.pathname.indexOf('/reg/');
        assert.equal(parsed.pathname.slice(i + 5), encodeURIComponent(client_id));
      });

    await fixture.agent.put(new URL(registration_client_uri).pathname)
      .auth(registration_access_token, { type: 'bearer' })
      .send({
        client_id,
        redirect_uris: ['https://client.example.com/cb2'],
      })
      .expect(200)
      .expect((response) => {
        ({ registration_access_token, registration_client_uri } = response.body);

        const parsed = new URL(registration_client_uri);
        assert.equal(parsed.search.length, 0);
        const i = parsed.pathname.indexOf('/reg/');
        assert.equal(parsed.pathname.slice(i + 5), encodeURIComponent(client_id));
      });

    await fixture.agent.delete(new URL(registration_client_uri).pathname)
      .auth(registration_access_token, { type: 'bearer' })
      .expect(204);
  });
});
