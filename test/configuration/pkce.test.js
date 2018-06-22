const { expect } = require('chai');

const Provider = require('../../lib');

describe('Provider configuration', () => {
  it('validates features.pkce.supportedMethods members', () => {
    const throws = [
      () => {
        new Provider('http://localhost:3000', { // eslint-disable-line no-new
          features: {
            pkce: {
              supportedMethods: ['S256', 'plain', 'foobar'],
            },
          },
        });
      },
      () => {
        new Provider('http://localhost:3000', { // eslint-disable-line no-new
          features: {
            pkce: {
              supportedMethods: ['foobar'],
            },
          },
        });
      },
    ];

    throws.forEach((fn) => {
      expect(fn).to.throw('only plain and S256 code challenge methods are supported');
    });
  });

  it('validates features.pkce.supportedMethods presence', () => {
    expect(() => {
      new Provider('http://localhost:3000', { // eslint-disable-line no-new
        features: {
          pkce: {
            supportedMethods: [],
          },
        },
      });
    }).to.throw('supportedMethods must not be empty');
  });

  it('validates features.pkce.supportedMethods type', () => {
    expect(() => {
      new Provider('http://localhost:3000', { // eslint-disable-line no-new
        features: {
          pkce: {
            supportedMethods: 'public',
          },
        },
      });
    }).to.throw('supportedMethods must be an array');
  });
});
