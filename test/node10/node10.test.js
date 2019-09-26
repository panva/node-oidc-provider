const { expect } = require('chai');

const { Provider } = require('../../lib');

const [major] = process.version.substr(1).split('.').map((x) => parseInt(x, 10));

if (major === 10) {
  describe('node 10 unsupported features', () => {
    it('mtls can not be enabled', () => {
      expect(() => {
        new Provider('http://localhost', { // eslint-disable-line no-new
          features: {
            mTLS: { enabled: true },
          },
        });
      }).to.throw('mTLS can only be enabled on Node.js >= 12.0.0 runtime');
    });

    it('paseto can not be enabled', () => {
      expect(() => {
        new Provider('http://localhost', { // eslint-disable-line no-new
          formats: { AccessToken: 'paseto' },
        });
      }).to.throw('paseto structured tokens can only be enabled on Node.js >= 12.0.0 runtime');
    });

    it('dynamic paseto results in an Error', async () => {
      const provider = new Provider('http://localhost', { // eslint-disable-line no-new
        formats: { AccessToken() { return 'paseto'; } },
      });

      const accessToken = new provider.AccessToken();

      try {
        await accessToken.save();
        throw new Error('expexted save to throw');
      } catch (err) {
        expect(err.message).to.eql('paseto structured tokens can only be enabled on Node.js >= 12.0.0 runtime');
      }
    });
  });
}
