const { expect } = require('chai');
const sinon = require('sinon');

const { Provider } = require('../../lib');

describe('provider instance', () => {
  context('draft/experimental spec warnings', () => {
    /* eslint-disable no-console */
    before(() => {
      sinon.stub(console, 'info').callsFake(() => {});
    });

    after(() => {
      console.info.restore();
    });

    afterEach(() => {
      console.info.resetHistory();
    });

    it('it warns when draft/experimental specs are enabled', () => {
      new Provider('http://localhost', { // eslint-disable-line no-new
        features: { sessionManagement: { enabled: true } },
      });

      expect(console.info.called).to.be.true;
    });

    it('it is silent when a version is acknowledged', () => {
      new Provider('http://localhost', { // eslint-disable-line no-new
        features: { sessionManagement: { enabled: true, ack: 28 } },
      });

      expect(console.info.called).to.be.false;
    });

    it('it is silent when a version is acknowledged where the draft is backwards compatible with a previous draft', () => {
      new Provider('http://localhost', { // eslint-disable-line no-new
        features: { resourceIndicators: { enabled: true, ack: 2 } },
      });

      expect(console.info.called).to.be.false;
    });

    it('throws when an acked feature has breaking changes since', () => {
      expect(() => {
        new Provider('http://localhost', { // eslint-disable-line no-new
          features: { sessionManagement: { enabled: true, ack: 27 } },
        });
      }).to.throw('An unacknowledged version of a draft feature is included in this oidc-provider version.');
      expect(console.info.called).to.be.true;
    });
    /* eslint-enable */
  });

  describe('provider.Client#find', () => {
    it('ignores non-string inputs', async () => {
      const provider = new Provider('http://localhost');
      expect(await provider.Client.find([])).to.be.undefined;
      expect(await provider.Client.find(Buffer)).to.be.undefined;
      expect(await provider.Client.find({})).to.be.undefined;
      expect(await provider.Client.find(true)).to.be.undefined;
      expect(await provider.Client.find(undefined)).to.be.undefined;
      expect(await provider.Client.find(64)).to.be.undefined;
    });
  });

  describe('provider.Client keystore lazy behaviour', () => {
    it('instantiates keystore and its HS derived keys lazily', async () => {
      const provider = new Provider('http://localhost', {
        clients: [{
          client_id: 'foo',
          client_secret: 'foobar',
          redirect_uris: ['https://rp.example.com'],
          token_endpoint_auth_method: 'client_secret_jwt',
          token_endpoint_auth_signing_alg: 'HS256',
          id_token_encrypted_response_alg: 'dir',
          id_token_encrypted_response_enc: 'A128CBC-HS256',
        }],
        features: {
          encryption: { enabled: true },
          requestObjects: {
            request: false,
            requestUri: false,
          },
        },
        whitelistedJWA: {
          idTokenEncryptionAlgValues: ['dir'],
        },
      });

      const client = await provider.Client.find('foo');
      let lazy = i(client).lazyAlgs;
      expect(lazy).to.be.ok;
      expect(lazy.size).to.eql(2);
      expect(client.keystore.size).to.eql(0);
      expect([...lazy]).to.eql(['HS256', 'A128CBC-HS256']);
      expect(client.keystore.get()).to.be.undefined;
      expect(client.keystore.get({ alg: 'HS256' })).to.be.ok;
      expect(client.keystore.size).to.eql(1);
      expect(lazy.size).to.eql(1);
      expect(client.keystore.get({ alg: 'A128CBC-HS256' })).to.be.ok;
      expect(client.keystore.size).to.eql(2);
      expect(lazy.size).to.eql(0);
      lazy = i(client).lazyAlgs;
      expect(lazy).to.be.undefined;
    });

    it('instantiates keystore and its HS derived keys lazily even if there is jwks already', async () => {
      const provider = new Provider('http://localhost', {
        clients: [{
          client_id: 'foo',
          client_secret: 'foobar',
          redirect_uris: ['https://rp.example.com'],
          token_endpoint_auth_method: 'client_secret_jwt',
          token_endpoint_auth_signing_alg: 'HS256',
          id_token_encrypted_response_alg: 'dir',
          id_token_encrypted_response_enc: 'A128CBC-HS256',
          jwks: {
            keys: [
              {
                e: 'AQAB',
                n: 'thyd94GamW5pbQBWAM-TJIX5Fy2T-3J83cONeelhb71nWc_RC1UoobE0iu4LKs9cDAJpXiAjdzbwqS87n7bGU6smXgeA5xCjDh9ukw1TN2F4k5YwHuQEUvk_esss53vHfN2s0C1XXdwy3HxDtzD23UKt7wQB1YsLBS8S3VUk-ruNuUTYRGW0ho-sfoe7TDWiS10eS3GPxJJixhvcA-GrH1KtPDJAAkR3UNFBOY6XQRRoovD5IColB81ycr2eLWJofbn0O_TZXSOEu5thIjKayFIOYsKH2ogBIArJefckcxR-jYGtFTv9nqkWMzKyi_wo-ipfrNaKILDp3TEALYu8_Q',
                kty: 'RSA',
                kid: 'O8ndoV8gKPCRVHnBebuL_b-rIfdRc8et4-z5tlTLLgw',
              },
            ],
          },
        }],
        features: {
          encryption: { enabled: true },
          requestObjects: {
            request: false,
            requestUri: false,
          },
        },
        whitelistedJWA: {
          idTokenEncryptionAlgValues: ['dir'],
        },
      });

      const client = await provider.Client.find('foo');
      let lazy = i(client).lazyAlgs;
      expect(lazy).to.be.ok;
      expect(lazy.size).to.eql(2);
      expect(client.keystore.size).to.eql(1);
      expect([...lazy]).to.eql(['HS256', 'A128CBC-HS256']);
      expect(client.keystore.get({ alg: 'HS256' })).to.be.ok;
      expect(client.keystore.size).to.eql(2);
      expect(lazy.size).to.eql(1);
      expect(client.keystore.get({ alg: 'A128CBC-HS256' })).to.be.ok;
      expect(client.keystore.size).to.eql(3);
      expect(lazy.size).to.eql(0);
      lazy = i(client).lazyAlgs;
      expect(lazy).to.be.undefined;
    });
  });

  describe('#urlFor', () => {
    it('returns the route for unprefixed issuers', () => {
      const provider = new Provider('http://localhost');
      expect(provider.urlFor('authorization')).to.equal('http://localhost/auth');
    });

    it('returns the route for prefixed issuers (1/2)', () => {
      const provider = new Provider('http://localhost/op/2.0');
      expect(provider.urlFor('authorization')).to.equal('http://localhost/op/2.0/auth');
    });

    it('returns the route for prefixed issuers (2/2)', () => {
      const provider = new Provider('http://localhost/op/2.0/');
      expect(provider.urlFor('authorization')).to.equal('http://localhost/op/2.0/auth');
    });

    it('passes the options', () => {
      const provider = new Provider('http://localhost');
      expect(provider.urlFor('resume', { uid: 'foo' })).to.equal('http://localhost/auth/foo');
    });
  });
});
