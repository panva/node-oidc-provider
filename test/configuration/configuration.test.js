const { expect } = require('chai');

const Configuration = require('../../lib/helpers/configuration');

describe('Provider configuration', () => {
  it('checks that a feature configuration property is valid', () => {
    expect(() => {
      new Configuration({ // eslint-disable-line no-new
        features: {
          foo: {},
        },
      });
    }).to.throw('Unknown feature configuration: foo');
  });
});
