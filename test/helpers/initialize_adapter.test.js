const { expect } = require('chai');

const initializeAdapter = require('../../lib/helpers/initialize_adapter');

describe('initializeAdapter helper', () => {
  it('throws when adapter is not a constructor or not a function', () => {
    expect(initializeAdapter.bind(undefined, {})).to.throw('Expected "adapter" to be a constructor or a factory function, provide a valid adapter in Provider config.');
    expect(initializeAdapter.bind(undefined, async () => {})).to.throw('Expected "adapter" to be a constructor or a factory function, provide a valid adapter in Provider config.');
  });

  it('should be success if argument is static method of class', () => {
    expect(
      initializeAdapter.bind(undefined, (class { static method() {} }).method),
    ).to.be.not.throw;
  });

  it('should be success if argument is arrow function', () => {
    expect(
      initializeAdapter.bind(undefined, () => {}).method,
    ).to.be.not.throw;
  });
});
