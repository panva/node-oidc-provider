'use strict';

const { expect } = require('chai');
const redirectUri = require('../../lib/helpers/redirect_uri');

describe('redirectUri helper', function () {
  it('does not modify the redirect_uri when it does not have path', function () {
    const result = redirectUri('http://client.example.com', {
      some: 'payload'
    });

    expect(result).to.equal('http://client.example.com?some=payload');
  });

  it('extends the query if part of the redirect_uri', function () {
    const result = redirectUri('http://client.example.com?other=stuff', {
      some: 'payload'
    });

    expect(result).to.equal('http://client.example.com?other=stuff&some=payload');
  });

  it('payload comes first', function () {
    const result = redirectUri('http://client.example.com?some=paylod', {
      some: 'other payload'
    });

    expect(result).to.equal('http://client.example.com?some=other%20payload');
  });

  it('works with fragment', function () {
    const result = redirectUri('http://client.example.com/', {
      some: 'payload'
    }, 'fragment');

    expect(result).to.equal('http://client.example.com/#some=payload');
  });

  it('works with fragment and keeps query', function () {
    const result = redirectUri('http://client.example.com?present=query', {
      some: 'payload'
    }, 'fragment');

    expect(result).to.equal('http://client.example.com?present=query#some=payload');
  });
});
