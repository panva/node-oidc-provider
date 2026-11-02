import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import Provider from '../../lib/index.js';

describe('Provider declaring support for refresh_token grant type', () => {
  it('is enabled by default', { timeout: 3000 }, () => {
    const provider = new Provider('https://op.example.com');
    assert.ok(i(provider).configuration.grantTypes.has('refresh_token'));
  });

  it('isnt enabled when offline_access isnt amongst the scopes', { timeout: 3000 }, () => {
    const provider = new Provider('https://op.example.com', { scopes: ['openid'] });
    assert.ok(!(i(provider).configuration.grantTypes.has('refresh_token')));
  });

  it('is enabled when offline_access isnt amongst the scopes', { timeout: 3000 }, () => {
    const provider = new Provider('https://op.example.com', { scopes: ['openid', 'offline_access'] });
    assert.ok(i(provider).configuration.grantTypes.has('refresh_token'));
  });

  it('is enabled when issueRefreshToken configuration function is configured', { timeout: 3000 }, () => {
    const provider = new Provider('https://op.example.com', {
      scopes: ['openid'],
      issueRefreshToken() {
        return true;
      },
    });
    assert.ok(i(provider).configuration.grantTypes.has('refresh_token'));
  });
});
