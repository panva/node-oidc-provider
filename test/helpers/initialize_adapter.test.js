import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import initializeAdapter from '../../lib/helpers/initialize_adapter.js';
import Provider from '../../lib/index.js';
import instance from '../../lib/helpers/weak_cache.js';

describe('initializeAdapter helper', () => {
  it('throws when adapter is not a constructor or not a function', { timeout: 3000 }, () => {
    assert.throws(initializeAdapter.bind(undefined, {}), (error) => { assert.ok(error.message.includes('Expected "adapter" to be a constructor or a factory function, provide a valid adapter in Provider config.')); return true; });
    assert.throws(initializeAdapter.bind(undefined, async () => {}), (error) => { assert.ok(error.message.includes('Expected "adapter" to be a constructor or a factory function, provide a valid adapter in Provider config.')); return true; });
  });

  it('should be success if argument is static method of class', { timeout: 3000 }, () => {
    // biome-ignore lint/complexity/noStaticOnlyClass: verifies static method adapter detection
    class CustomAdapter {
      static method() {}
    }
    const provider = new Provider('https://op.example.com');
    assert.doesNotThrow(() => initializeAdapter.call(provider, CustomAdapter.method));
    assert.equal(instance(provider).Adapter, CustomAdapter.method);
  });

  it('should be success if argument is arrow function', { timeout: 3000 }, () => {
    const provider = new Provider('https://op.example.com');
    const adapter = () => {};
    assert.doesNotThrow(() => initializeAdapter.call(provider, adapter));
    assert.equal(instance(provider).Adapter, adapter);
  });
});
