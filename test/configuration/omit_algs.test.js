import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK } from 'jose';

import Provider from '../../lib/index.js';

describe('Provider declaring supported algorithms', () => {
  it('validates the configuration properties', { timeout: 3000 }, () => {
    assert.throws(() => {
      new Provider('https://op.example.com', {
        enabledJWA: {
          invalidProperty: ['HS256', 'RS256'],
        },
      });
    }, (error) => { assert.ok(error.message.includes('invalid property enabledJWA.invalidProperty provided')); return true; });
  });

  it('validates an array is provided', { timeout: 3000 }, () => {
    assert.throws(() => {
      new Provider('https://op.example.com', {
        enabledJWA: {
          idTokenSigningAlgValues: new Set(['HS256', 'RS256']),
        },
      });
    }, (error) => { assert.ok(error.message.includes('invalid type for enabledJWA.idTokenSigningAlgValues provided, expected Array')); return true; });
  });

  it('validates only implemented algs are provided', { timeout: 3000 }, () => {
    assert.throws(() => {
      new Provider('https://op.example.com', {
        enabledJWA: {
          clientAuthSigningAlgValues: ['none'],
        },
      });
    }, (error) => { assert.ok(error.message.includes('unsupported enabledJWA.clientAuthSigningAlgValues algorithm provided')); return true; });
  });

  it('idTokenSigningAlgValues', { timeout: 3000 }, async () => {
    const { privateKey } = await generateKeyPair('RS256', { extractable: true });
    const provider = new Provider('https://op.example.com', {
      enabledJWA: {
        idTokenSigningAlgValues: ['HS256', 'RS256'],
      },
      jwks: {
        keys: [await exportJWK(privateKey)],
      },
    });

    assert.deepEqual(i(provider).configuration.idTokenSigningAlgValues, ['HS256', 'RS256']);
  });
});
