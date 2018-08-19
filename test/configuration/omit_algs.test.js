const { expect } = require('chai');

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
        keys: [{
          kty: 'RSA',
          kid: 'qASZ4PJ2cQRHt65V6aUTOGvhp6A8VSD6K5HGpkf50Cw',
          e: 'AQAB',
          n: 'kVBdsvbFktbujcZrqzrwkC6FxLMfTt-b3P--OuGvZME6PIqOtcpVzr-sngY7XIdPghYI9_w0zD8qkC3gOh8twQ',
          d: 'iefvRIyVbIm1067fN52z9-Fu6gHkUII99TpwWokcX0zZLpxFkCTwmJEJmK-m5uO5Xbg8fQ2OSoFliUhDGhXTwQ',
          p: '9Vj_BurQcHfU-4W0-hINkmn6MCJe9pLoY0j89dQUDxU',
          q: 'l5-CbNKwAIP45DFBXnA3hOE-bdAGRSe1DTTb8WLcrv0',
          dp: 'Z5kZrrkOJL9kzoQp5AIlevKG8zZANQvZVrsmHUNc6PU',
          dq: 'gCEFgJzSqrzbmUqeaQX_hMUrknTWt54Ee_KNYwEeaKk',
          qi: 'VaLM9_zxhtOgpHPMTVsbS_rBNH6-gY3bc854224X2EQ',
        }],
      },
    }).then(fail, (err) => {
      expect(i(provider).configuration('idTokenSigningAlgValues')).to.eql(['HS256', 'RS256']);
      expect(err).to.have.property('error_description').matches(/^id_token_signed_response_alg/);
    });
  });
});
