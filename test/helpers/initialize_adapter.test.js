const { expect } = require('chai');

const initializeAdapter = require('../../lib/helpers/initialize_adapter');

describe('initializeAdapter helper', () => {
  it('throws when adapter is not a constructor', () => {
    initializeAdapter(() => {}).catch(err => expect(err.message).to.be.equal(
      'Expected "adapter" to be a constructor, provide a valid adapter in Provider config.',
    ));
  });
});
