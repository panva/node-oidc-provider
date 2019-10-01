const { expect } = require('chai');
const jose = require('jose');

const { Provider } = require('../../lib');

describe('Provider declaring supported algorithms', () => {
  it('validates the configuration properties', () => {
    expect(() => {
      new Provider('https://op.example.com', { // eslint-disable-line no-new
        whitelistedJWA: {
          invalidProperty: ['HS256', 'RS256'],
        },
      });
    }).to.throw('invalid property whitelistedJWA.invalidProperty provided');
  });

  it('validates an array is provided', () => {
    expect(() => {
      new Provider('https://op.example.com', { // eslint-disable-line no-new
        whitelistedJWA: {
          idTokenSigningAlgValues: new Set(['HS256', 'RS256']),
        },
      });
    }).to.throw('invalid type for whitelistedJWA.idTokenSigningAlgValues provided, expected Array');
  });

  it('validates only implemented algs are provided', () => {
    expect(() => {
      new Provider('https://op.example.com', { // eslint-disable-line no-new
        whitelistedJWA: {
          tokenEndpointAuthSigningAlgValues: ['none'],
        },
      });
    }).to.throw('unsupported whitelistedJWA.tokenEndpointAuthSigningAlgValues algorithm provided');
  });

  it('idTokenSigningAlgValues', () => {
    const provider = new Provider('https://op.example.com', {
      whitelistedJWA: {
        idTokenSigningAlgValues: ['HS256', 'RS256'],
      },
      jwks: {
        keys: [jose.JWK.generateSync('RSA').toJWK(true)],
      },
    });

    expect(i(provider).configuration('idTokenSigningAlgValues')).to.eql(['HS256', 'RS256']);
  });
});
