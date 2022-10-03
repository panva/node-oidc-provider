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

  it('checks that a stable feature does not have an ack', () => {
    expect(() => {
      new Configuration({ // eslint-disable-line no-new
        features: {
          deviceFlow: {
            enabled: true,
            ack: 'draft-01',
          },
        },
      });
    }).to.throw("deviceFlow feature is now stable, the ack draft-01 is no longer valid. Check the stable feature's configuration for any breaking changes.");
  });

  it('checks that a feature configuration is not a boolean', () => {
    expect(() => {
      new Configuration({ // eslint-disable-line no-new
        features: {
          devInteractions: false,
        },
      });
    }).to.throw('features are no longer enabled/disabled with a boolean value, please see the docs');
    expect(() => {
      new Configuration({ // eslint-disable-line no-new
        features: {
          devInteractions: true,
        },
      });
    }).to.throw('features are no longer enabled/disabled with a boolean value, please see the docs');
  });
});
