'use strict';

const { Provider } = require('../../lib');
const { expect } = require('chai');
const sinon = require('sinon');

describe('provider instance', function () {
  context('when in non test environment', function () {
    /* eslint-disable no-console */
    before(() => {
      delete process.env.NODE_ENV;
      sinon.stub(console, 'warn', () => {});
    });
    after(() => {
      process.env.NODE_ENV = 'test';
      console.warn.restore();
    });

    it('it warns when draft/experimental specs are enabled', function () {
      new Provider('http://localhost', { // eslint-disable-line no-new
        features: { sessionManagement: true }
      });

      expect(console.warn.calledOnce).to.be.true;
    });
    /* eslint-enable */
  });

  describe('#urlFor', function () {
    it('returns the route for unprefixed issuers', function () {
      const provider = new Provider('http://localhost');
      expect(provider.urlFor('authorization')).to.equal('http://localhost/auth');
    });

    it('returns the route for prefixed issuers', function () {
      const provider = new Provider('http://localhost/op/2.0');
      expect(provider.urlFor('authorization')).to.equal('http://localhost/op/2.0/auth');
    });

    it('passes the options', function () {
      const provider = new Provider('http://localhost');
      expect(provider.urlFor('resume', { grant: 'foo' })).to.equal('http://localhost/auth/foo');
    });
  });

  describe('#resume', function () {
    it('redirects the context, and sets a cookie', function () {
      const provider = new Provider('http://localhost');

      const ctx = { cookies: { set: sinon.spy() }, redirect: sinon.spy() };

      provider.resume(ctx, 'foo', {});

      expect(ctx.cookies.set.calledOnce).to.be.true;
      expect(ctx.cookies.set.firstCall.calledWith('_grant_result', '{}',
        {
          path: '/auth/foo',
          httpOnly: true,
          maxAge: 3600000,
          signed: true
        }
      )).to.be.true;
      expect(ctx.redirect.calledOnce).to.be.true;
      expect(ctx.redirect.firstCall.calledWith('http://localhost/auth/foo')).to.be.true;
    });
  });
});
