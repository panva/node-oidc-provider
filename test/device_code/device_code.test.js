import { describe, before, it } from 'node:test';
import assert from 'node:assert/strict';

import Provider from '../../lib/index.js';
import bootstrap from '../test_helper.js';

describe('configuration features.deviceFlow', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  it('can only be configured with digits and base-20 charset', { timeout: 3000 }, () => {
    assert.doesNotThrow(() => {
      new Provider('http://localhost', {
        features: {
          deviceFlow: {
            enabled: true,
            charset: 'digits',
          },
        },
      });
    });
    assert.doesNotThrow(() => {
      new Provider('http://localhost', {
        features: {
          deviceFlow: {
            enabled: true,
            charset: 'base-20',
          },
        },
      });
    });
    assert.throws(() => {
      new Provider('http://localhost', {
        features: {
          deviceFlow: {
            enabled: true,
            charset: 'foo',
          },
        },
      });
    }, (error) => { assert.ok(error.message.includes('only supported charsets are "base-20" and "digits"')); return true; });
  });

  it('can be configured with a mask', { timeout: 3000 }, () => {
    assert.doesNotThrow(() => {
      new Provider('http://localhost', {
        features: {
          deviceFlow: {
            enabled: true,
            mask: '*** *** ***',
          },
        },
      });
    });
    assert.doesNotThrow(() => {
      new Provider('http://localhost', {
        features: {
          deviceFlow: {
            enabled: true,
            mask: '***-***-***',
          },
        },
      });
    });
    assert.throws(() => {
      new Provider('http://localhost', {
        features: {
          deviceFlow: {
            enabled: true,
            mask: '***.***.***',
          },
        },
      });
    }, (error) => { assert.ok(error.message.includes('mask can only contain asterisk("*"), hyphen-minus("-") and space(" ") characters')); return true; });
  });

  it('extends discovery', { timeout: 3000 }, () => fixture.agent.get('/.well-known/openid-configuration')
      .expect(200)
      .expect((response) => {
        assert.ok(['device_authorization_endpoint'].every((key) => Object.keys(response.body).includes(key)));
      }));
});
