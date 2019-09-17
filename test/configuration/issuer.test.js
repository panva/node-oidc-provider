/* eslint-disable no-new */

const { strict: assert } = require('assert');

const { expect } = require('chai');

const { Provider } = require('../../lib');

describe('Provider issuer configuration', () => {
  it('validates the issuer input to be present and valid', () => {
    expect(() => {
      new Provider();
    }).to.throw(assert.AssertionError);
    expect(() => {
      new Provider({});
    }).to.throw(assert.AssertionError);
    expect(() => {
      new Provider(0);
    }).to.throw(assert.AssertionError);
    expect(() => {
      new Provider(true);
    }).to.throw(assert.AssertionError);
    expect(() => {
      new Provider('');
    }).to.throw(assert.AssertionError);
    expect(() => {
      new Provider('https://op.example.com?');
    }).to.throw(assert.AssertionError);
    expect(() => {
      new Provider('https://op.example.com?query');
    }).to.throw(assert.AssertionError);
    expect(() => {
      new Provider('https://op.example.com?query=complete');
    }).to.throw(assert.AssertionError);
    expect(() => {
      new Provider('https://op.example.com#fragment');
    }).to.throw(assert.AssertionError);
    expect(() => {
      new Provider('https://op.example.com?query=and#fragment');
    }).to.throw(assert.AssertionError);
    expect(() => {
      new Provider('foobar');
    }).to.throw(assert.AssertionError);
    expect(() => {
      new Provider('foobar:');
    }).to.throw(assert.AssertionError);
    expect(() => {
      new Provider('foobar://');
    }).to.throw(assert.AssertionError);
    expect(() => {
      new Provider('op.example.com');
    }).to.throw(assert.AssertionError);
    expect(() => {
      new Provider('op.example.com:443');
    }).to.throw(assert.AssertionError);
  });
});

/* eslint-enable no-new */
