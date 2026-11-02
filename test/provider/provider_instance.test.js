import { describe, before, after, afterEach, it } from 'node:test';
import assert from 'node:assert/strict';

import sinon from 'sinon';

import Provider from '../../lib/index.js';
import MemoryAdapter from '../../lib/adapters/memory_adapter.js';

describe('provider instance', () => {
  describe('draft/experimental spec warnings', () => {
    before(() => {
      sinon.stub(console, 'info').callsFake(() => {});
    }, { timeout: 3000 });

    after(() => {
      console.info.restore();
    }, { timeout: 3000 });

    afterEach(() => {
      console.info.resetHistory();
    }, { timeout: 3000 });

    it('it warns when draft/experimental specs are enabled', { timeout: 3000 }, () => {
      new Provider('http://localhost', {
        features: { webMessageResponseMode: { enabled: true } },
      });

      assert.equal(console.info.called, true);
    });

    it('it is silent when a version is acknowledged', { timeout: 3000 }, () => {
      new Provider('http://localhost', {
        features: { webMessageResponseMode: { enabled: true, ack: 'individual-draft-01' } },
      });

      assert.equal(console.info.called, false);
    });

    it('throws when an acked feature has breaking changes since', { timeout: 3000 }, () => {
      assert.throws(() => {
        new Provider('http://localhost', {
          features: { webMessageResponseMode: { enabled: true, ack: 'not a current version' } },
        });
      }, (error) => { assert.ok(error.message.includes('An unacknowledged version of an experimental feature is included in this oidc-provider version.')); return true; });
      assert.equal(console.info.called, true);
    });
  });

  describe('provider.Client#find', () => {
    it('ignores non-string inputs', { timeout: 3000 }, async () => {
      const provider = new Provider('http://localhost');
      assert.equal(await provider.Client.find([]), undefined);
      assert.equal(await provider.Client.find(Buffer), undefined);
      assert.equal(await provider.Client.find({}), undefined);
      assert.equal(await provider.Client.find(true), undefined);
      assert.equal(await provider.Client.find(undefined), undefined);
      assert.equal(await provider.Client.find(64), undefined);
    });
  });

  describe('#urlFor', () => {
    it('returns the route for unprefixed issuers', { timeout: 3000 }, () => {
      const provider = new Provider('http://localhost');
      assert.equal(provider.urlFor('authorization'), 'http://localhost/auth');
    });

    it('returns the route for prefixed issuers (1/2)', { timeout: 3000 }, () => {
      const provider = new Provider('http://localhost/op/2.0');
      assert.equal(provider.urlFor('authorization'), 'http://localhost/op/2.0/auth');
    });

    it('returns the route for prefixed issuers (2/2)', { timeout: 3000 }, () => {
      const provider = new Provider('http://localhost/op/2.0/');
      assert.equal(provider.urlFor('authorization'), 'http://localhost/op/2.0/auth');
    });

    it('passes the options', { timeout: 3000 }, () => {
      const provider = new Provider('http://localhost');
      assert.equal(provider.urlFor('resume', { uid: 'foo' }), 'http://localhost/auth/foo');
    });
  });

  describe('adapters', () => {
    const error = new Error('used this adapter');

    it('retains expired artifacts through the clock tolerance window', { timeout: 3000 }, async () => {
      const clock = sinon.useFakeTimers();

      try {
        const provider = new Provider('https://op.example.com', { clockTolerance: 1 });
        const request = new provider.BackchannelAuthenticationRequest({
          clientId: 'client',
          expiresIn: 1,
        });
        const authReqId = await request.save();

        clock.tick(1001);
        assert.ok(await provider.BackchannelAuthenticationRequest.find(authReqId) instanceof provider.BackchannelAuthenticationRequest);
        const expired = await provider.BackchannelAuthenticationRequest.find(authReqId, {
          ignoreExpiration: true,
        });
        ((actual) => { assert.ok('isExpired' in Object(actual)); assert.equal(actual.isExpired, true); })(expired);

        clock.tick(1000);
        assert.equal(await provider.BackchannelAuthenticationRequest.find(authReqId, {
          ignoreExpiration: true,
        }), undefined);
      } finally {
        clock.restore();
      }
    });

    for (const [label, configuration] of [
      ['implicit default', undefined],
      ['explicit default', { adapter: MemoryAdapter }],
    ]) {
      it(`isolates ${label} adapter storage per Provider`, { timeout: 3000 }, async () => {
        const first = new Provider('https://first.example.com', configuration);
        const second = new Provider('https://second.example.com', configuration);
        const payload = { kind: 'AccessToken' };

        await first.AccessToken.adapter.upsert('shared-id', payload, 60);

        assert.equal(await first.AccessToken.adapter.find('shared-id'), payload);
        assert.equal(await second.AccessToken.adapter.find('shared-id'), undefined);
      });
    }

    it('can be a class', { timeout: 3000 }, async () => {
      const provider = new Provider('https://op.example.com', {
        adapter: class {
          async find() {
            throw error;
          }
        },
      });
      await assert.rejects(provider.AccessToken.find('tokenValue'), {
        message: 'used this adapter',
      });
      await assert.rejects(provider.Client.find('clientId'), {
        message: 'used this adapter',
      });
    });

    it('can be a class static function', { timeout: 3000 }, async () => {
      const provider = new Provider('https://op.example.com', {
        // biome-ignore lint/complexity/noStaticOnlyClass: test intentionally uses a static-only class
        adapter: (class {
          static factory() {
            return {
              async find() {
                throw error;
              },
            };
          }
        }).factory,
      });
      await assert.rejects(provider.AccessToken.find('tokenValue'), {
        message: 'used this adapter',
      });
      await assert.rejects(provider.Client.find('clientId'), {
        message: 'used this adapter',
      });
    });

    it('can be an arrow function', { timeout: 3000 }, async () => {
      const provider = new Provider('https://op.example.com', {
        adapter: () => ({
          async find() {
            throw error;
          },
        }),
      });
      await assert.rejects(provider.AccessToken.find('tokenValue'), {
        message: 'used this adapter',
      });
      await assert.rejects(provider.Client.find('clientId'), {
        message: 'used this adapter',
      });
    });
  });
});
