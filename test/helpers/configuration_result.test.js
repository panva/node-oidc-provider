import { expect } from 'chai';

import {
  account,
  boolean,
  extraTokenClaims,
  positiveInteger,
  resourceServer,
} from '../../lib/helpers/configuration_result.js';

describe('configuration hook result validation', () => {
  it('validates strict Boolean results', () => {
    expect(boolean(true, 'example.policy')).to.be.true;
    expect(() => boolean(1, 'example.policy')).to.throw(
      TypeError,
      'example.policy must return a Boolean',
    );
  });

  it('validates positive integer TTL results', () => {
    expect(positiveInteger(60, 'ttl.AccessToken')).to.equal(60);
    for (const value of [0, -1, 1.5, Infinity, Promise.resolve(60)]) {
      expect(() => positiveInteger(value, 'ttl.AccessToken')).to.throw(
        TypeError,
        'ttl.AccessToken must return a positive integer',
      );
    }
  });

  it('validates account results', () => {
    const value = { accountId: 'account', claims() {} };
    expect(account(value)).to.equal(value);
    expect(account(undefined)).to.be.undefined;
    expect(() => account({ accountId: '', claims() {} })).to.throw(
      TypeError,
      'findAccount must return undefined or an object with a non-empty accountId and a claims function',
    );
  });

  it('validates resource server results', () => {
    const value = { scope: 'api:read', accessTokenTTL: 60, accessTokenFormat: 'jwt' };
    expect(resourceServer(value)).to.equal(value);
    expect(resourceServer({
      scope: 'api:read',
      audience: undefined,
      accessTokenTTL: undefined,
      accessTokenFormat: undefined,
    })).to.deep.equal({
      scope: 'api:read',
      audience: undefined,
      accessTokenTTL: undefined,
      accessTokenFormat: undefined,
    });
    expect(() => resourceServer(undefined)).to.throw(
      TypeError,
      'features.resourceIndicators.getResourceServerInfo must return an object',
    );
    expect(() => resourceServer({ scope: [] })).to.throw(
      TypeError,
      'features.resourceIndicators.getResourceServerInfo must return an object with a scope string',
    );
    expect(() => resourceServer({ scope: 'api:read', accessTokenTTL: 1.5 })).to.throw(
      TypeError,
      'features.resourceIndicators.getResourceServerInfo.accessTokenTTL must return a positive integer',
    );
  });

  it('validates additional token claims', () => {
    expect(extraTokenClaims(undefined)).to.be.undefined;
    expect(extraTokenClaims({ role: 'admin' })).to.deep.equal({ role: 'admin' });
    expect(() => extraTokenClaims([])).to.throw(
      TypeError,
      'extraTokenClaims must return undefined or a plain object',
    );
  });
});
