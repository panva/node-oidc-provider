import { expect } from 'chai';
import { createSandbox } from 'sinon';
import { shouldWriteCookies } from '../../lib/helpers/cookie_helpers.js';
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

    it('returns true when no cookie configuration is set (default behavior)', () => {
      expect(shouldWriteCookies(mockCtx)).to.be.true;
    });

    it('returns false when doNotSet is true', () => {
      mockInstance.configuration.cookies.doNotSet = true;
      
      expect(shouldWriteCookies(mockCtx)).to.be.false;
    });

    it('returns true when doNotSet is false', () => {
      mockInstance.configuration.cookies.doNotSet = false;
      
      expect(shouldWriteCookies(mockCtx)).to.be.true;
    });

    it('uses custom shouldWriteCookies function when provided', () => {
      const customFunction = sinon.stub().returns(false);
      mockInstance.configuration.cookies.shouldWriteCookies = customFunction;
      
      const result = shouldWriteCookies(mockCtx);
      
      expect(customFunction.calledOnce).to.be.true;
      expect(customFunction.calledWith(mockCtx)).to.be.true;
      expect(result).to.be.false;
    });

    it('custom shouldWriteCookies function overrides doNotSet configuration', () => {
      const customFunction = sinon.stub().returns(true);
      mockInstance.configuration.cookies.shouldWriteCookies = customFunction;
      mockInstance.configuration.cookies.doNotSet = true; // This should be ignored
      
      const result = shouldWriteCookies(mockCtx);
      
      expect(customFunction.calledOnce).to.be.true;
      expect(result).to.be.true; // Custom function returned true, overriding doNotSet
    });

    it('falls back to doNotSet when custom function is not a function', () => {
      mockInstance.configuration.cookies.shouldWriteCookies = 'not-a-function';
      mockInstance.configuration.cookies.doNotSet = true;
      
      expect(shouldWriteCookies(mockCtx)).to.be.false;
    });

    it('falls back to doNotSet when custom function is undefined', () => {
      mockInstance.configuration.cookies.shouldWriteCookies = undefined;
      mockInstance.configuration.cookies.doNotSet = true;
      
      expect(shouldWriteCookies(mockCtx)).to.be.false;
    });

    it('custom function receives correct context parameter', () => {
      const customFunction = sinon.stub().returns(true);
      mockInstance.configuration.cookies.shouldWriteCookies = customFunction;
      
      mockCtx.customProperty = 'test-value';
      shouldWriteCookies(mockCtx);
      
      const calledWithCtx = customFunction.getCall(0).args[0];
      expect(calledWithCtx.customProperty).to.equal('test-value');
      expect(calledWithCtx.oidc).to.equal(mockCtx.oidc);
    });
  });
});