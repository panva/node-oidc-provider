import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import Provider from '../../lib/index.js';

describe('custom claims', () => {
  it('allows for claims to be added under openid scope using array syntax', { timeout: 3000 }, () => {
    const provider = new Provider('https://op.example.com', {
      claims: {
        openid: ['foo'],
      },
    });

    assert.deepEqual(i(provider).configuration.claims.openid, {
      sub: null,
      foo: null,
    });
  });

  it('allows for claims to be added under openid scope using object syntax', { timeout: 3000 }, () => {
    const provider = new Provider('https://op.example.com', {
      claims: {
        openid: { foo: null },
      },
    });

    assert.deepEqual(i(provider).configuration.claims.openid, {
      sub: null,
      foo: null,
    });
  });

  it('detects new scopes from claims definition', { timeout: 3000 }, () => {
    const provider = new Provider('https://op.example.com', {
      claims: {
        insurance: ['company_name', 'coverage'],
        payment: {
          preferred_method: null,
        },
      },
    });

    assert.ok(i(provider).configuration.scopes.has('insurance'));
  });

  it('removes the acr claim if no acrs are configured', { timeout: 3000 }, () => {
    const provider = new Provider('https://op.example.com', {
      acrValues: [],
    });

    assert.ok(!(i(provider).configuration.claimsSupported.has('acr')));
  });
});
