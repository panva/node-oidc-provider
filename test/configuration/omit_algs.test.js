const { expect } = require('chai');
const jose = require('@panva/jose');

const Provider = require('../../lib');

const fail = () => { throw new Error('expected promise to be rejected'); };

const client = {
  client_id: 'foo',
  client_secret: 'atleast32byteslongforHS256mmkay?',
  redirect_uris: ['https://client.example.com/cb'],
};

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
    });

    expect(i(provider).configuration('idTokenSigningAlgValues')).to.eql(['HS256']);

    return provider.initialize({
      clients: [
        Object.assign({
          id_token_signed_response_alg: 'HS384',
        }, client),
      ],
      keystore: {
        keys: [jose.JWK.generateSync('RSA').toJWK(true)],
      },
    }).then(fail, (err) => {
      expect(i(provider).configuration('idTokenSigningAlgValues')).to.eql(['HS256', 'RS256']);
      expect(err).to.have.property('error_description').matches(/^id_token_signed_response_alg/);
    });
  });
});
