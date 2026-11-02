import { describe, before, it } from 'node:test';
import assert from 'node:assert/strict';

import bootstrap from '../test_helper.js';

describe('Client#add', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture, { config: 'client_secrets' }), { timeout: 3000 });

  it('client secret is mandatory if client auth needs it', { timeout: 3000 }, () => {
    assert.equal(fixture.provider.Client.needsSecret({
      token_endpoint_auth_method: 'client_secret_basic',
    }), true);
  });
});
