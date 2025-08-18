import { expect } from 'chai';
import { createSandbox } from 'sinon';
import { shouldWriteCookies, clearAllCookies } from '../../lib/helpers/cookie_helpers.js';

const sinon = createSandbox();

describe('session cookie logic integration', () => {
  let mockCtx;
  let mockProvider;
  let mockInstance;

  beforeEach(async () => {
    mockProvider = {
      cookieName: sinon.stub(),
      configuration: {
        cookies: {}
      }
    };
    
    mockProvider.cookieName.withArgs('interaction').returns('_interaction');
    mockProvider.cookieName.withArgs('resume').returns('_resume');
    mockProvider.cookieName.withArgs('session').returns('_session');
    
    mockInstance = {
      configuration: mockProvider.configuration
    };
    
    mockCtx = {
      oidc: {
        provider: mockProvider
      },
      cookies: {
        set: sinon.spy()
      }
    };
    
    // Mock the instance cache
    const { set: setInstance } = await import('../../lib/helpers/weak_cache.js');
    setInstance(mockProvider, mockInstance);
  });

  afterEach(() => {
    sinon.restore();
  });

  describe('cookie clearing behavior', () => {
    it('clearAllCookies removes all relevant cookies', () => {
      clearAllCookies(mockCtx);
      
      expect(mockCtx.cookies.set.calledThrice).to.be.true;
      expect(mockCtx.cookies.set.calledWith('_interaction', null)).to.be.true;
      expect(mockCtx.cookies.set.calledWith('_resume', null)).to.be.true;
      expect(mockCtx.cookies.set.calledWith('_session', null)).to.be.true;
    });

    it('uses correct cookie names from provider', () => {
      clearAllCookies(mockCtx);
      
      expect(mockProvider.cookieName.calledWith('interaction')).to.be.true;
      expect(mockProvider.cookieName.calledWith('resume')).to.be.true;
      expect(mockProvider.cookieName.calledWith('session')).to.be.true;
    });
  });

  describe('shouldWriteCookies integration with clearAllCookies', () => {
    it('should clear cookies when shouldWriteCookies returns false', () => {
      mockInstance.configuration.cookies.doNotSet = true;
      
      const shouldWrite = shouldWriteCookies(mockCtx);
      expect(shouldWrite).to.be.false;
      
      if (!shouldWrite) {
        clearAllCookies(mockCtx);
      }
      
      expect(mockCtx.cookies.set.calledThrice).to.be.true;
    });

    it('should not clear cookies when shouldWriteCookies returns true', () => {
      mockInstance.configuration.cookies.doNotSet = false;
      
      const shouldWrite = shouldWriteCookies(mockCtx);
      expect(shouldWrite).to.be.true;
      
      if (!shouldWrite) {
        clearAllCookies(mockCtx);
      }
      
      expect(mockCtx.cookies.set.called).to.be.false;
    });

    it('should use custom shouldWriteCookies function and clear appropriately', () => {
      const customFunction = sinon.stub().returns(false);
      mockInstance.configuration.cookies.shouldWriteCookies = customFunction;
      
      const shouldWrite = shouldWriteCookies(mockCtx);
      expect(shouldWrite).to.be.false;
      expect(customFunction.calledWith(mockCtx)).to.be.true;
      
      if (!shouldWrite) {
        clearAllCookies(mockCtx);
      }
      
      expect(mockCtx.cookies.set.calledThrice).to.be.true;
    });
  });
});