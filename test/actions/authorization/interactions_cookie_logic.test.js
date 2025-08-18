import { expect } from 'chai';
import { createSandbox } from 'sinon';
import { shouldWriteCookies, clearAllCookies } from '../../../lib/helpers/cookie_helpers.js';

const sinon = createSandbox();

describe('interactions cookie logic integration', () => {
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
    const { set: setInstance } = await import('../../../lib/helpers/weak_cache.js');
    setInstance(mockProvider, mockInstance);
  });

  afterEach(() => {
    sinon.restore();
  });

  describe('interaction middleware cookie behavior', () => {
    it('should clear cookies when shouldWriteCookies returns false', () => {
      mockInstance.configuration.cookies.doNotSet = true;
      
      const shouldWrite = shouldWriteCookies(mockCtx);
      expect(shouldWrite).to.be.false;
      
      // Simulate the interaction middleware behavior
      if (shouldWrite) {
        mockCtx.cookies.set('_interaction', 'interaction-uid', {
          httpOnly: true,
          maxAge: 3600 * 1000
        });
      } else {
        clearAllCookies(mockCtx);
      }
      
      expect(mockCtx.cookies.set.calledThrice).to.be.true;
      expect(mockCtx.cookies.set.calledWith('_interaction', null)).to.be.true;
      expect(mockCtx.cookies.set.calledWith('_resume', null)).to.be.true;
      expect(mockCtx.cookies.set.calledWith('_session', null)).to.be.true;
    });

    it('should set interaction cookie when shouldWriteCookies returns true', () => {
      mockInstance.configuration.cookies.doNotSet = false;
      
      const shouldWrite = shouldWriteCookies(mockCtx);
      expect(shouldWrite).to.be.true;
      
      // Simulate the interaction middleware behavior
      if (shouldWrite) {
        mockCtx.cookies.set('_interaction', 'interaction-uid', {
          httpOnly: true,
          maxAge: 3600 * 1000
        });
      } else {
        clearAllCookies(mockCtx);
      }
      
      expect(mockCtx.cookies.set.calledOnce).to.be.true;
      expect(mockCtx.cookies.set.calledWith('_interaction', 'interaction-uid', {
        httpOnly: true,
        maxAge: 3600 * 1000
      })).to.be.true;
    });

    it('should handle custom shouldWriteCookies function in interaction flow', () => {
      const customFunction = sinon.stub().returns(true);
      mockInstance.configuration.cookies.shouldWriteCookies = customFunction;
      
      const shouldWrite = shouldWriteCookies(mockCtx);
      expect(shouldWrite).to.be.true;
      expect(customFunction.calledWith(mockCtx)).to.be.true;
      
      // Simulate interaction middleware setting cookie when allowed
      if (shouldWrite) {
        mockCtx.cookies.set('_interaction', 'interaction-uid', {
          httpOnly: true,
          maxAge: 3600 * 1000
        });
      } else {
        clearAllCookies(mockCtx);
      }
      
      expect(mockCtx.cookies.set.calledOnce).to.be.true;
      expect(mockCtx.cookies.set.calledWith('_interaction', 'interaction-uid')).to.be.true;
    });
  });
});