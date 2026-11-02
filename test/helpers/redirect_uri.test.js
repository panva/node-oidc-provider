import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import redirectUri from '../../lib/helpers/redirect_uri.js';

describe('redirectUri helper', () => {
  it('does not modify the redirect_uri when it does not have path', { timeout: 3000 }, () => {
    const result = redirectUri('http://client.example.com', {
      some: 'payload',
    });

    assert.equal(result, 'http://client.example.com/?some=payload');
  });

  it('extends the query if part of the redirect_uri', { timeout: 3000 }, () => {
    const result = redirectUri('http://client.example.com/?other=stuff', {
      some: 'payload',
    });

    assert.equal(result, 'http://client.example.com/?other=stuff&some=payload');
  });

  it('payload comes first', { timeout: 3000 }, () => {
    const result = redirectUri('http://client.example.com/?some=paylod', {
      some: 'other payload',
    });

    assert.equal(result, 'http://client.example.com/?some=other+payload');
  });

  it('works with fragment', { timeout: 3000 }, () => {
    const result = redirectUri('http://client.example.com/', {
      some: 'payload',
    }, 'fragment');

    assert.equal(result, 'http://client.example.com/#some=payload');
  });

  it('works with fragment and keeps query', { timeout: 3000 }, () => {
    const result = redirectUri('http://client.example.com/?present=query', {
      some: 'payload',
    }, 'fragment');

    assert.equal(result, 'http://client.example.com/?present=query#some=payload');
  });
});
