import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  account,
  boolean,
  extraTokenClaims,
  positiveInteger,
  resourceServer,
} from '../../lib/helpers/configuration_result.js';

describe('configuration hook result validation', () => {
  it('validates strict Boolean results', { timeout: 3000 }, () => {
    assert.equal(boolean(true, 'example.policy'), true);
    assert.throws(() => boolean(1, 'example.policy'), (error) => { assert.ok(error instanceof TypeError); assert.ok(error.message.includes('example.policy must return a Boolean')); return true; });
  });

  it('validates positive integer TTL results', { timeout: 3000 }, () => {
    assert.equal(positiveInteger(60, 'ttl.AccessToken'), 60);
    for (const value of [0, -1, 1.5, Infinity, Promise.resolve(60)]) {
      assert.throws(() => positiveInteger(value, 'ttl.AccessToken'), (error) => { assert.ok(error instanceof TypeError); assert.ok(error.message.includes('ttl.AccessToken must return a positive integer')); return true; });
    }
  });

  it('validates account results', { timeout: 3000 }, () => {
    const value = { accountId: 'account', claims() {} };
    assert.equal(account(value), value);
    assert.equal(account(undefined), undefined);
    assert.throws(() => account({ accountId: '', claims() {} }), (error) => { assert.ok(error instanceof TypeError); assert.ok(error.message.includes('findAccount must return undefined or an object with a non-empty accountId and a claims function')); return true; });
  });

  it('validates resource server results', { timeout: 3000 }, () => {
    const value = { scope: 'api:read', accessTokenTTL: 60, accessTokenFormat: 'jwt' };
    assert.equal(resourceServer(value), value);
    assert.deepEqual(resourceServer({
      scope: 'api:read',
      audience: undefined,
      accessTokenTTL: undefined,
      accessTokenFormat: undefined,
    }), {
      scope: 'api:read',
      audience: undefined,
      accessTokenTTL: undefined,
      accessTokenFormat: undefined,
    });
    assert.throws(() => resourceServer(undefined), (error) => { assert.ok(error instanceof TypeError); assert.ok(error.message.includes('features.resourceIndicators.getResourceServerInfo must return an object')); return true; });
    assert.throws(() => resourceServer({ scope: [] }), (error) => { assert.ok(error instanceof TypeError); assert.ok(error.message.includes('features.resourceIndicators.getResourceServerInfo must return an object with a scope string')); return true; });
    assert.throws(() => resourceServer({ scope: 'api:read', accessTokenTTL: 1.5 }), (error) => { assert.ok(error instanceof TypeError); assert.ok(error.message.includes('features.resourceIndicators.getResourceServerInfo.accessTokenTTL must return a positive integer')); return true; });
  });

  it('validates additional token claims', { timeout: 3000 }, () => {
    assert.equal(extraTokenClaims(undefined), undefined);
    assert.deepEqual(extraTokenClaims({ role: 'admin' }), { role: 'admin' });
    assert.throws(() => extraTokenClaims([]), (error) => { assert.ok(error instanceof TypeError); assert.ok(error.message.includes('extraTokenClaims must return undefined or a plain object')); return true; });
  });
});
