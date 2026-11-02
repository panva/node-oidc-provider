import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import Provider from '../../lib/index.js';

describe('Provider configuration', () => {
  it('validates subjectTypes members', { timeout: 3000 }, () => {
    const throws = [
      () => {
        new Provider('http://localhost:3000', {
          subjectTypes: ['public', 'pairwise', 'foobar'],
        });
      },
      () => {
        new Provider('http://localhost:3000', {
          subjectTypes: ['foobar'],
        });
      },
    ];

    throws.forEach((fn) => {
      assert.throws(fn, (error) => { assert.ok(error.message.includes('only public and pairwise subjectTypes are supported')); return true; });
    });
  });

  it('validates subjectTypes presence', { timeout: 3000 }, () => {
    assert.throws(() => {
      new Provider('http://localhost:3000', {
        subjectTypes: [],
      });
    }, (error) => { assert.ok(error.message.includes('subjectTypes must not be empty')); return true; });
  });
});
