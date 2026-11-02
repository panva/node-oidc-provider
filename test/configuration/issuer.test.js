import { describe, it } from 'node:test';
import assert from 'node:assert/strict';


import Provider from '../../lib/index.js';

describe('Provider issuer configuration', () => {
  it('validates the issuer input to be present and valid', { timeout: 3000 }, () => {
    assert.throws(() => {
      new Provider();
    }, (error) => { assert.ok(error instanceof assert.AssertionError); return true; });
    assert.throws(() => {
      new Provider({});
    }, (error) => { assert.ok(error instanceof assert.AssertionError); return true; });
    assert.throws(() => {
      new Provider(0);
    }, (error) => { assert.ok(error instanceof assert.AssertionError); return true; });
    assert.throws(() => {
      new Provider(true);
    }, (error) => { assert.ok(error instanceof assert.AssertionError); return true; });
    assert.throws(() => {
      new Provider('');
    }, (error) => { assert.ok(error instanceof assert.AssertionError); return true; });
    assert.throws(() => {
      new Provider('https://op.example.com?');
    }, (error) => { assert.ok(error instanceof assert.AssertionError); return true; });
    assert.throws(() => {
      new Provider('https://op.example.com?query');
    }, (error) => { assert.ok(error instanceof assert.AssertionError); return true; });
    assert.throws(() => {
      new Provider('https://op.example.com?query=complete');
    }, (error) => { assert.ok(error instanceof assert.AssertionError); return true; });
    assert.throws(() => {
      new Provider('https://op.example.com#fragment');
    }, (error) => { assert.ok(error instanceof assert.AssertionError); return true; });
    assert.throws(() => {
      new Provider('https://op.example.com?query=and#fragment');
    }, (error) => { assert.ok(error instanceof assert.AssertionError); return true; });
    assert.throws(() => {
      new Provider('foobar');
    }, (error) => { assert.ok(error instanceof assert.AssertionError); return true; });
    assert.throws(() => {
      new Provider('foobar:');
    }, (error) => { assert.ok(error instanceof assert.AssertionError); return true; });
    assert.throws(() => {
      new Provider('foobar://');
    }, (error) => { assert.ok(error instanceof assert.AssertionError); return true; });
    assert.throws(() => {
      new Provider('op.example.com');
    }, (error) => { assert.ok(error instanceof assert.AssertionError); return true; });
    assert.throws(() => {
      new Provider('op.example.com:443');
    }, (error) => { assert.ok(error instanceof assert.AssertionError); return true; });
  });
});

