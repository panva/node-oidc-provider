/* eslint-disable no-new */

const jose = require('node-jose');
const { expect } = require('chai');
const Provider = require('../../lib');

const integrity = jose.JWK.createKeyStore();
const fail = () => { throw new Error('expected promise to be rejected'); };

describe('configuration.integrity', function () {
  it('must contain atleast one key', function () {
    const provider = new Provider('http://localhost');

    return provider.initialize({ integrity }).then(fail, function (err) {
      expect(err.message).to.equal('at least one key must be provided in integrity keystore');
    });
  });

  context('', function () {
    before(function () {
      return integrity.generate('oct', 512, { alg: 'HS512' });
    });
    it('can be initialized with an object', function () {
      const provider = new Provider('http://localhost');
      return provider.initialize({ integrity: integrity.toJSON(true) });
    });
    it('can be initialized with a jose.JWK.KeyStore', function () {
      const provider = new Provider('http://localhost');
      return provider.initialize({ integrity });
    });
  });
});
