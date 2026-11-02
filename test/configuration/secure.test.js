import { describe, beforeEach, afterEach, before, it } from 'node:test';
import assert from 'node:assert/strict';
import sinon from 'sinon';

import bootstrap from '../test_helper.js';

describe('x-forwarded-proto trust', () => {
  const fixture = {};

  beforeEach(() => {
    sinon.stub(console, 'warn').returns();
  }, { timeout: 3000 });

  afterEach(() => console.warn.restore(), { timeout: 3000 });

  const acceptUnauthorized = { tls: { rejectUnauthorized: false } };

  describe('when trusted', () => {
    const fixture1 = Object.create(fixture);

    before(bootstrap(import.meta.url, fixture1, { protocol: 'https:' }), { timeout: 3000 });
    it('is trusted when proxy=true is set on the koa app', { timeout: 3000 }, async () => {
      if (fixture1.app) {
        fixture1.app.proxy = true;
      } else {
        fixture1.provider.proxy = true;
      }
      await fixture1.agent.get('/.well-known/openid-configuration', acceptUnauthorized)
        .set('x-forwarded-proto', 'https')
        .expect(200)
        .expect(/"authorization_endpoint":"https:/);

      await fixture1.agent.get('/.well-known/openid-configuration', acceptUnauthorized)
        .set('x-forwarded-proto', 'https')
        .expect(200)
        .expect(/"authorization_endpoint":"https:/);

      assert.equal(console.warn.called, false);
    });
  });
});
