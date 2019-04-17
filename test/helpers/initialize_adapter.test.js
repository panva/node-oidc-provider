const { expect } = require('chai');

const initializeAdapter = require('../../lib/helpers/initialize_adapter');

describe('initializeAdapter helper', () => {
  it('throws when adapter is not a constructor', () => {
    expect(initializeAdapter.bind(undefined, {})).to.throw('Expected "adapter" to be a constructor, provide a valid adapter in Provider config.');
  });
});
