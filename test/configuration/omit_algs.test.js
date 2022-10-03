const { expect } = require('chai');
const jose = require('jose2');

const { Provider } = require('../../lib');

describe('Provider declaring supported algorithms', () => {
  it('validates the configuration properties', () => {
    expect(() => {
      new Provider('https://op.example.com', { // eslint-disable-line no-new
        enabledJWA: {
          invalidProperty: ['HS256', 'RS256'],
        },
      });
    }).to.throw('invalid property enabledJWA.invalidProperty provided');
  });

  it('validates an array is provided', () => {
    expect(() => {
      new Provider('https://op.example.com', { // eslint-disable-line no-new
        enabledJWA: {
          idTokenSigningAlgValues: new Set(['HS256', 'RS256']),
        },
      });
    }).to.throw('invalid type for enabledJWA.idTokenSigningAlgValues provided, expected Array');
  });

  it('validates only implemented algs are provided', () => {
    expect(() => {
      new Provider('https://op.example.com', { // eslint-disable-line no-new
        enabledJWA: {
          tokenEndpointAuthSigningAlgValues: ['none'],
        },
      });
    }).to.throw('unsupported enabledJWA.tokenEndpointAuthSigningAlgValues algorithm provided');
  });

  it('idTokenSigningAlgValues', () => {
    const provider = new Provider('https://op.example.com', {
      enabledJWA: {
        idTokenSigningAlgValues: ['HS256', 'RS256'],
      },
      jwks: {
        keys: [jose.JWK.generateSync('RSA').toJWK(true)],
      },
    });

    expect(i(provider).configuration('idTokenSigningAlgValues')).to.eql(['HS256', 'RS256']);
  });
});
