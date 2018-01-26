require('../test_helper');
const { expect } = require('chai');
const Provider = require('../../lib');

const fail = () => { throw new Error('expected promise to be rejected'); };

describe('provider.Client', () => {
  describe('#cacheClear()', () => {
    before(function () {
      return new Provider('http://localhost:3000').initialize({
        clients: [{ client_id: 'fixed', client_secret: 'foobar', redirect_uris: ['http://rp.example.com/cb'] }],
      }).then((provider) => {
        this.provider = provider;
      });
    });

    it('keeps the fixed clients in cache', async function () {
      expect(await this.provider.Client.find('fixed')).to.be.ok;
      this.provider.Client.cacheClear();
      expect(await this.provider.Client.find('fixed')).to.be.ok;
    });

    it('removes the adapter backed ones from cache', async function () {
      await i(this.provider).clientAdd({
        client_id: 'client',
        client_secret: 'secret',
        redirect_uris: ['https://client.example.com/cb'],
      });

      expect(await this.provider.Client.find('client')).to.be.ok;
      this.provider.Client.cacheClear();
      expect(await this.provider.Client.find('client')).not.to.be.ok;
    });

    it('keeps the fixed client in cache given id', async function () {
      expect(await this.provider.Client.find('fixed')).to.be.ok;
      this.provider.Client.cacheClear('fixed');
      expect(await this.provider.Client.find('fixed')).to.be.ok;
    });

    it('removes the adapter backed client from cache given id', async function () {
      await i(this.provider).clientAdd({
        client_id: 'client',
        client_secret: 'secret',
        redirect_uris: ['https://client.example.com/cb'],
      });
      expect(await this.provider.Client.find('client')).to.be.ok;
      this.provider.Client.cacheClear('client');
      expect(await this.provider.Client.find('client')).not.to.be.ok;
    });

    it('removes only wanted adapter backed client from cache', async function () {
      await i(this.provider).clientAdd({
        client_id: 'client',
        client_secret: 'secret',
        redirect_uris: ['https://client.example.com/cb'],
      });
      await i(this.provider).clientAdd({
        client_id: 'clientStay',
        client_secret: 'secret',
        redirect_uris: ['https://client.example.com/cb'],
      });
      expect(await this.provider.Client.find('client')).to.be.ok;
      expect(await this.provider.Client.find('clientStay')).to.be.ok;
      this.provider.Client.cacheClear('client');
      expect(await this.provider.Client.find('client')).not.to.be.ok;
      expect(await this.provider.Client.find('clientStay')).to.be.ok;
      this.provider.Client.cacheClear('clientStay');
    });

    it('leaves adapter backed clients intact in case of not found', async function () {
      await i(this.provider).clientAdd({
        client_id: 'client',
        client_secret: 'secret',
        redirect_uris: ['https://client.example.com/cb'],
      });
      expect(await this.provider.Client.find('client')).to.be.ok;
      this.provider.Client.cacheClear('another');
      expect(await this.provider.Client.find('client')).to.be.ok;
      this.provider.Client.cacheClear('client');
    });

    it('has a Schema class getter that can work its magic', async function () {
      expect(this.provider.Client.Schema).to.be.ok;

      const client = {
        client_id: 'client',
        token_endpoint_auth_method: 'none',
        response_types: ['id_token'],
        grant_types: ['implicit'],
        redirect_uris: ['http://client.example.com/cb'],
      };

      await i(this.provider).clientAdd(client).then(fail, (err) => {
        expect(err).to.be.an('error');
        expect(err.message).to.eql('invalid_redirect_uri');
      });

      this.provider.Client.Schema.prototype.redirectUris = () => {};
      await i(this.provider).clientAdd(client);
    });
  });
});
