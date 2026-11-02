import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import Provider from '../../lib/index.js';

describe('pathFor related behaviors', () => {
  it('throws an Error when invalid route path is requested', { timeout: 3000 }, () => {
    const provider = new Provider('http://localhost');
    assert.equal(provider.pathFor('authorization'), '/auth');
    assert.throws(() => provider.pathFor('foobar'), (error) => { assert.ok(error instanceof Error); assert.ok(error.message.includes('No route found for name: foobar')); return true; });
  });

  it('interactionUrl resolves to /interaction/uid when devInteractions is disabled', { timeout: 3000 }, async () => {
    const provider = new Provider('http://localhost', {
      features: {
        devInteractions: { enabled: false },
      },
    });

    const url = await i(provider).configuration.interactions.url({}, new provider.Interaction('foobar', {}));

    assert.equal(url, '/interaction/foobar');
  });
});
