const { expect } = require('chai');

const { Provider } = require('../../lib');

describe('custom claims', () => {
  it('allows for claims to be added under openid scope using array syntax', () => {
    const provider = new Provider('https://op.example.com', {
      claims: {
        openid: ['foo'],
      },
    });

    expect(provider.configuration('claims').get('openid')).to.eql({
      sub: null,
      foo: null,
    });
  });

  it('allows for claims to be added under openid scope using object syntax', () => {
    const provider = new Provider('https://op.example.com', {
      claims: {
        openid: { foo: null },
      },
    });

    expect(provider.configuration('claims').get('openid')).to.eql({
      sub: null,
      foo: null,
    });
  });

  it('detects new scopes from claims definition', () => {
    const foo = /^foo:\d+$/;
    const bar = /^bar:\d+$/;
    const claims = new Map(Object.entries({
      insurance: ['company_name', 'coverage'],
      payment: {
        preferred_method: null,
      },
    }));
    claims.set(foo, ['foo']);
    claims.set(foo, { bar: null });

    const provider = new Provider('https://op.example.com', {
      claims,
    });

    expect(provider.configuration('scopes')).to.contain('insurance', 'payment');
    expect(provider.configuration('dynamicScopes')).to.contain(foo, bar);
  });

  it('removes the acr claim if no acrs are configured', () => {
    const provider = new Provider('https://op.example.com', {
      acrValues: [],
    });

    expect(provider.configuration('claimsSupported')).not.to.contain('acr');
  });
});
