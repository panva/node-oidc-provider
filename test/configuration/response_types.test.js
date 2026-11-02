import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import Provider from '../../lib/index.js';

describe('response_types Provider configuration', () => {
  it('fixes common issues', { timeout: 3000 }, () => {
    const provider = new Provider('https://op.example.com', {
      responseTypes: ['token id_token code', 'token id_token'],
    });
    assert.deepEqual(i(provider).configuration.responseTypes, ['code id_token token', 'id_token token']);
  });

  it('throws when invalid types are configured', { timeout: 3000 }, () => {
    assert.throws(() => {
      new Provider('https://op.example.com', {
        responseTypes: ['id_token tokencode'],
      });
    }, (error) => { assert.ok(error.message.includes('unsupported response type: id_token tokencode')); return true; });
  });

  it('throws when unsupported types are configured', { timeout: 3000 }, () => {
    assert.throws(() => {
      new Provider('https://op.example.com', {
        responseTypes: ['token'],
      });
    }, (error) => { assert.ok(error.message.includes('unsupported response type: token')); return true; });
  });

  it('validates none is always standalone', { timeout: 3000 }, () => {
    assert.throws(() => {
      new Provider('https://op.example.com', {
        responseTypes: ['none code'],
      });
    }, (error) => { assert.ok(error.message.includes('unsupported response type: none code')); return true; });
  });
});
