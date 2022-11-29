import { expect } from 'chai';

import Provider from '../../lib/index.js';

describe('custom claims', () => {
  it('allows for claims to be added under openid scope using array syntax', () => {
    const provider = new Provider('https://op.example.com', {
      claims: {
        openid: ['foo'],
      },
    });

    expect(i(provider).configuration('claims').openid).to.eql({
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

    expect(i(provider).configuration('claims').openid).to.eql({
      sub: null,
      foo: null,
    });
  });

  it('detects new scopes from claims definition', () => {
    const provider = new Provider('https://op.example.com', {
      claims: {
        insurance: ['company_name', 'coverage'],
        payment: {
          preferred_method: null,
        },
      },
    });

    expect(i(provider).configuration('scopes')).to.contain('insurance', 'payment');
  });

  it('removes the acr claim if no acrs are configured', () => {
    const provider = new Provider('https://op.example.com', {
      acrValues: [],
    });

    expect(i(provider).configuration('claimsSupported')).not.to.contain('acr');
  });
});
