'use strict';

const { expect } = require('chai');
const { Provider } = require('../../lib');

describe('Provider#addKey', function () {
  it('validates pairwiseSalt presence when pairwise is configured', function (done) {
    const provider = new Provider('http://localhost:3000', {
      subjectTypes: ['public']
    });

    provider.addKey({
      kty: 'RSA',
      kid: 's3E__cEVIVmdLBehy4-ydQVYBvF4kINk9P52tuFR0Xk',
      e: 'AQAB',
      n: 'in5NgR5JNZV_NyfUIELtlfUqzJSSKugI_LNpLcBH-bM'
    }).then((jwk) => {
      expect(jwk).not.to.be.ok; // don't wanna accept public keys here
    }, (err) => {
      expect(err).to.be.an('Error');
      expect(err.message).to.equal('only private keys should be added');
      expect(provider.keystore.get('s3E__cEVIVmdLBehy4-ydQVYBvF4kINk9P52tuFR0Xk')).to.be.null; // the added key should be removed
    }).then(done, done);
  });
});
