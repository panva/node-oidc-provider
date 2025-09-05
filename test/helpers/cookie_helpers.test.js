import { expect } from 'chai';
import { createSandbox } from 'sinon';
import { shouldWriteCookies, clearAllCookies } from '../../lib/helpers/cookie_helpers.js';
import { set as setInstance } from '../../lib/helpers/weak_cache.js';

const sinon = createSandbox();

describe('cookie helpers', () => {
  describe('shouldWriteCookies', () => {
    let mockCtx;
    let mockProvider;
    let mockInstance;

    beforeEach(() => {
      mockProvider = {
        configuration: {
          cookies: {}
        }
      };
      
      mockInstance = {
        configuration: mockProvider.configuration
      };
      
      mockCtx = {
        oidc: {
          provider: mockProvider,
          params: {}
        },
        query: {}
      };
      
      // Mock the instance cache to return our mock configuration
      setInstance(mockProvider, mockInstance);
    });

    afterEach(() => {
      sinon.restore();
    });

    it('returns true when no cookie configuration is set (default behavior)', async () => {
      expect(await shouldWriteCookies(mockCtx)).to.be.true;
    });

    it('returns false when doNotSet is true', async () => {
      mockInstance.configuration.cookies.doNotSet = true;
      
      expect(await shouldWriteCookies(mockCtx)).to.be.false;
    });

    it('returns true when doNotSet is false', async () => {
      mockInstance.configuration.cookies.doNotSet = false;
      
      expect(await shouldWriteCookies(mockCtx)).to.be.true;
    });

    it('uses custom shouldWriteCookies function when provided', async () => {
      const customFunction = sinon.stub().returns(false);
      mockInstance.configuration.cookies.shouldWriteCookies = customFunction;
      
      const result = await shouldWriteCookies(mockCtx);
      
      expect(customFunction.calledOnce).to.be.true;
      expect(customFunction.calledWith(mockCtx)).to.be.true;
      expect(result).to.be.false;
    });

    it('custom shouldWriteCookies function overrides doNotSet configuration', async () => {
      const customFunction = sinon.stub().returns(true);
      mockInstance.configuration.cookies.shouldWriteCookies = customFunction;
      mockInstance.configuration.cookies.doNotSet = true; // This should be ignored
      
      const result = await shouldWriteCookies(mockCtx);
      
      expect(customFunction.calledOnce).to.be.true;
      expect(result).to.be.true; // Custom function returned true, overriding doNotSet
    });

    it('falls back to doNotSet when custom function is not a function', async () => {
      mockInstance.configuration.cookies.shouldWriteCookies = 'not-a-function';
      mockInstance.configuration.cookies.doNotSet = true;
      
      expect(await shouldWriteCookies(mockCtx)).to.be.false;
    });

    it('falls back to doNotSet when custom function is undefined', async () => {
      mockInstance.configuration.cookies.shouldWriteCookies = undefined;
      mockInstance.configuration.cookies.doNotSet = true;
      
      expect(await shouldWriteCookies(mockCtx)).to.be.false;
    });

    it('custom function receives correct context parameter', async () => {
      const customFunction = sinon.stub().returns(true);
      mockInstance.configuration.cookies.shouldWriteCookies = customFunction;
      
      mockCtx.customProperty = 'test-value';
      await shouldWriteCookies(mockCtx);
      
      const calledWithCtx = customFunction.getCall(0).args[0];
      expect(calledWithCtx.customProperty).to.equal('test-value');
      expect(calledWithCtx.oidc).to.equal(mockCtx.oidc);
    });

    it('handles async custom shouldWriteCookies function', async () => {
      const asyncCustomFunction = sinon.stub().callsFake(async () => {
        return new Promise(resolve => {
          setTimeout(() => resolve(false), 10);
        });
      });
      mockInstance.configuration.cookies.shouldWriteCookies = asyncCustomFunction;
      
      const result = await shouldWriteCookies(mockCtx);
      
      expect(asyncCustomFunction.calledOnce).to.be.true;
      expect(asyncCustomFunction.calledWith(mockCtx)).to.be.true;
      expect(result).to.be.false;
    });
  });

  describe('clearAllCookies', () => {
    let mockCtx;
    let mockProvider;
    let mockCookies;

    beforeEach(() => {
      mockCookies = {
        set: sinon.spy()
      };
      
      mockProvider = {
        cookieName: sinon.stub()
      };
      
      mockProvider.cookieName.withArgs('interaction').returns('_interaction');
      mockProvider.cookieName.withArgs('resume').returns('_resume');
      mockProvider.cookieName.withArgs('session').returns('_session');
      
      mockCtx = {
        cookies: mockCookies,
        oidc: {
          provider: mockProvider
        }
      };
    });

    afterEach(() => {
      sinon.restore();
    });

    it('clears interaction, resume, and session cookies', () => {
      clearAllCookies(mockCtx);
      
      expect(mockCookies.set.calledThrice).to.be.true;
      expect(mockCookies.set.calledWith('_interaction', null)).to.be.true;
      expect(mockCookies.set.calledWith('_resume', null)).to.be.true;
      expect(mockCookies.set.calledWith('_session', null)).to.be.true;
    });

    it('uses provider cookieName method to get correct cookie names', () => {
      clearAllCookies(mockCtx);
      
      expect(mockProvider.cookieName.calledWith('interaction')).to.be.true;
      expect(mockProvider.cookieName.calledWith('resume')).to.be.true;
      expect(mockProvider.cookieName.calledWith('session')).to.be.true;
    });
  });
});