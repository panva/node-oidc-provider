'use strict';

const Provider = require('../../lib');
const { expect } = require('chai');

describe('custom claims', function () {
  it('allows for claims to be added under openid scope using array syntax', function () {
    const provider = new Provider('https://op.example.com', {
      claims: {
        openid: ['foo'],
      },
    });

    expect(i(provider).configuration('claims.openid')).to.eql({
      sub: null,
      foo: null,
    });
  });

  it('allows for claims to be added under openid scope using object syntax', function () {
    const provider = new Provider('https://op.example.com', {
      claims: {
        openid: { foo: null },
      },
    });

    expect(i(provider).configuration('claims.openid')).to.eql({
      sub: null,
      foo: null,
    });
  });

  it('detects new scopes from claims definition', function () {
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

  it('removes the acr claim if no acrs are configured', function () {
    const provider = new Provider('https://op.example.com', {
      acrValues: [],
    });

    expect(i(provider).configuration('claimsSupported')).not.to.contain('acr');
  });
});
