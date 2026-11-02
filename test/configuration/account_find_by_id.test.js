import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import Provider from '../../lib/index.js';

describe('default findAccount behavior', () => {
  it('returns a promise', { timeout: 3000 }, () => {
    const provider = new Provider('http://localhost');

    assert.equal(i(provider).configuration.findAccount({}, 'id') instanceof Promise, true);
  });

  it('resolves to an object with property and accountId property and claims function', { timeout: 3000 }, () => {
    const provider = new Provider('http://localhost');

    return i(provider).configuration.findAccount({}, 'id').then(async (account) => {
      assert.equal(account.accountId, 'id');
      assert.deepEqual(await account.claims(), { sub: 'id' });
    });
  });
});
