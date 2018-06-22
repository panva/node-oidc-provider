const { expect } = require('chai');
const sinon = require('sinon');

const Provider = require('../../lib');

describe('provider instance', () => {
  context('when in non test environment', () => {
    /* eslint-disable no-console */
    before(() => {
      delete process.env.NODE_ENV;
      sinon.stub(console, 'info').callsFake(() => {});
    });
    after(() => {
      process.env.NODE_ENV = 'test';
      console.info.restore();
    });

    it('it warns when draft/experimental specs are enabled', () => {
      new Provider('http://localhost', { // eslint-disable-line no-new
        features: { sessionManagement: true },
      });

      expect(console.info.called).to.be.true;
    });
    /* eslint-enable */
  });

  describe('#initialize', () => {
    it('does not allow to be initialized twice', (done) => {
      const provider = new Provider('http://localhost');
      provider.initialize({ keystore: {} }).catch(() => {
        provider.initialize().then(() => {
          expect(() => { provider.initialize(); }).to.throw('already initialized');
          done();
        });
      });
      expect(() => { provider.initialize(); }).to.throw('already initializing');
    });
  });

  describe('#urlFor', () => {
    it('returns the route for unprefixed issuers', () => {
      const provider = new Provider('http://localhost');
      return provider.initialize({}).then(() => {
        expect(provider.urlFor('authorization')).to.equal('http://localhost/auth');
      });
    });

    it('returns the route for prefixed issuers', () => {
      const provider = new Provider('http://localhost/op/2.0');
      return provider.initialize({}).then(() => {
        expect(provider.urlFor('authorization')).to.equal('http://localhost/op/2.0/auth');
      });
    });

    it('passes the options', () => {
      const provider = new Provider('http://localhost');
      return provider.initialize({}).then(() => {
        expect(provider.urlFor('resume', { grant: 'foo' })).to.equal('http://localhost/auth/foo');
      });
    });
  });

  describe('provider#defaultHttpOptions=', () => {
    it('can be set to follow redirects', () => {
      const provider = new Provider('http://localhost');
      provider.defaultHttpOptions = { followRedirect: true };
      expect(provider.defaultHttpOptions).to.have.property('followRedirect', true);
    });

    it('can be set to send more headers by default', () => {
      const provider = new Provider('http://localhost');
      expect(provider.defaultHttpOptions).to.have.nested.property('headers.User-Agent')
        .to.match(/^oidc-provider.+\(http:\/\/localhost\)/);
      provider.defaultHttpOptions = { headers: { 'X-Meta-Id': 'meta meta' } };
      expect(provider.defaultHttpOptions).to.have.nested.property('headers.User-Agent')
        .to.match(/^oidc-provider.+\(http:\/\/localhost\)/);
      expect(provider.defaultHttpOptions).to.have.nested.property('headers.X-Meta-Id', 'meta meta');
    });

    it('can overwrite the timeout', () => {
      const provider = new Provider('http://localhost');
      provider.defaultHttpOptions = { timeout: 2500 };
      expect(provider.defaultHttpOptions).to.have.property('timeout', 2500);
    });
  });
});
