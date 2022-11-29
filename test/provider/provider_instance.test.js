/* eslint-disable max-classes-per-file */

import { strict as assert } from 'node:assert';

import { expect } from 'chai';
import sinon from 'sinon';

import Provider from '../../lib/index.js';

describe('provider instance', () => {
  context('draft/experimental spec warnings', () => {
    /* eslint-disable no-console */
    before(() => {
      sinon.stub(console, 'info').callsFake(() => {});
    });

    after(() => {
      console.info.restore();
    });

    afterEach(() => {
      console.info.resetHistory();
    });

    it('it warns when draft/experimental specs are enabled', () => {
      new Provider('http://localhost', { // eslint-disable-line no-new
        features: { webMessageResponseMode: { enabled: true } },
      });

      expect(console.info.called).to.be.true;
    });

    it('it is silent when a version is acknowledged', () => {
      new Provider('http://localhost', { // eslint-disable-line no-new
        features: { webMessageResponseMode: { enabled: true, ack: 'individual-draft-00' } },
      });

      expect(console.info.called).to.be.false;
    });

    it('it is silent when a version is acknowledged where the draft is backwards compatible with a previous draft', () => {
      new Provider('http://localhost', { // eslint-disable-line no-new
        features: { webMessageResponseMode: { enabled: true, ack: 'id-00' } },
      });

      expect(console.info.called).to.be.false;
    });

    it('throws when an acked feature has breaking changes since', () => {
      expect(() => {
        new Provider('http://localhost', { // eslint-disable-line no-new
          features: { webMessageResponseMode: { enabled: true, ack: 'not a current version' } },
        });
      }).to.throw('An unacknowledged version of a draft feature is included in this oidc-provider version.');
      expect(console.info.called).to.be.true;
    });
    /* eslint-enable */
  });

  describe('provider.Client#find', () => {
    it('ignores non-string inputs', async () => {
      const provider = new Provider('http://localhost');
      expect(await provider.Client.find([])).to.be.undefined;
      expect(await provider.Client.find(Buffer)).to.be.undefined;
      expect(await provider.Client.find({})).to.be.undefined;
      expect(await provider.Client.find(true)).to.be.undefined;
      expect(await provider.Client.find(undefined)).to.be.undefined;
      expect(await provider.Client.find(64)).to.be.undefined;
    });
  });

  describe('#urlFor', () => {
    it('returns the route for unprefixed issuers', () => {
      const provider = new Provider('http://localhost');
      expect(provider.urlFor('authorization')).to.equal('http://localhost/auth');
    });

    it('returns the route for prefixed issuers (1/2)', () => {
      const provider = new Provider('http://localhost/op/2.0');
      expect(provider.urlFor('authorization')).to.equal('http://localhost/op/2.0/auth');
    });

    it('returns the route for prefixed issuers (2/2)', () => {
      const provider = new Provider('http://localhost/op/2.0/');
      expect(provider.urlFor('authorization')).to.equal('http://localhost/op/2.0/auth');
    });

    it('passes the options', () => {
      const provider = new Provider('http://localhost');
      expect(provider.urlFor('resume', { uid: 'foo' })).to.equal('http://localhost/auth/foo');
    });
  });

  describe('adapters', () => {
    const error = new Error('used this adapter');

    it('can be a class', async () => {
      const provider = new Provider('https://op.example.com', {
        adapter: class {
          // eslint-disable-next-line
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

    it('can be a class static function', async () => {
      const provider = new Provider('https://op.example.com', {
        adapter: (class {
          // eslint-disable-next-line
          static factory() {
            // eslint-disable-next-line
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

    it('can be an arrow function', async () => {
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
