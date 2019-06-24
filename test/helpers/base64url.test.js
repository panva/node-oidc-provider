const { expect } = require('chai');

const base64url = require('../../lib/helpers/base64url');

describe('base64url', () => {
  it('checks that the input is valid base64url', () => {
    expect(() => {
      base64url.decode('foo=');
    }).to.throw(TypeError, 'input is not a valid base64url encoded string');
    expect(() => {
      base64url.decodeToBuffer('foo=', 'hex');
    }).to.throw(TypeError, 'input is not a valid base64url encoded string');
  });
});
