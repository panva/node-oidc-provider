'use strict';

require('../test_helper');
const { expect } = require('chai');
const Provider = require('../../lib');

describe('provider.Client', function () {
  describe('#cacheClear()', function () {
    before(function () {
      return new Provider('http://localhost:3000').initialize({
        clients: [{ client_id: 'fixed', client_secret: 'foobar', redirect_uris: ['http://rp.example.com/cb'] }],
      }).then((provider) => {
        this.provider = provider;
      });
    });

    it('keeps the fixed clients in cache', function* () {
      expect(yield this.provider.Client.find('fixed')).to.be.ok;
      this.provider.Client.cacheClear();
      expect(yield this.provider.Client.find('fixed')).to.be.ok;
    });

    it('removes the adapter backed ones from cache', function* () {
      yield i(this.provider).clientAdd({
        client_id: 'client',
        client_secret: 'secret',
        redirect_uris: ['https://client.example.com/cb'],
      });

      expect(yield this.provider.Client.find('client')).to.be.ok;
      this.provider.Client.cacheClear();
      expect(yield this.provider.Client.find('client')).not.to.be.ok;
    });
  });
});
