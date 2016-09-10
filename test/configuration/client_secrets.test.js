'use strict';

const bootstrap = require('../test_helper');
const { expect } = require('chai');

describe('Provider#addClient', function () {
  const { provider } = bootstrap(__dirname);
  provider.setupCerts();

  [
    'id_token_signed_response_alg',
    'request_object_signing_alg',
    'token_endpoint_auth_signing_alg',
    'userinfo_signed_response_alg'
  ].forEach(function (metadata) {
    context(`configuring ${metadata} when secrets are not long enough`, function () {
      it('validates the secret length (HS256)', function () {
        return provider.addClient({
          client_id: `${Math.random()}`,
          client_secret: 'not32bytes_____________________',
          redirect_uris: ['https://client.example.com/cb'],
          [metadata]: 'HS256'
        }).then(function (client) {
          expect(client).not.to.be.ok;
        }, function (err) {
          expect(err).to.be.ok;
          expect(err).to.have.property('message', 'invalid_client_metadata');
          expect(err).to.have.property('error_description', 'insufficient client_secret length');
        });
      });

      it('validates the secret length (HS384)', function () {
        return provider.addClient({
          client_id: `${Math.random()}`,
          client_secret: 'not48bytes_____________________________________',
          redirect_uris: ['https://client.example.com/cb'],
          [metadata]: 'HS384'
        }).then(function (client) {
          expect(client).not.to.be.ok;
        }, function (err) {
          expect(err).to.be.ok;
          expect(err).to.have.property('message', 'invalid_client_metadata');
          expect(err).to.have.property('error_description', 'insufficient client_secret length');
        });
      });

      it('validates the secret length (HS512)', function () {
        return provider.addClient({
          client_id: `${Math.random()}`,
          client_secret: 'not64bytes_____________________________________________________',
          redirect_uris: ['https://client.example.com/cb'],
          [metadata]: 'HS512'
        }).then(function (client) {
          expect(client).not.to.be.ok;
        }, function (err) {
          expect(err).to.be.ok;
          expect(err).to.have.property('message', 'invalid_client_metadata');
          expect(err).to.have.property('error_description', 'insufficient client_secret length');
        });
      });
    });

    context(`configuring ${metadata} when secrets are long enough`, function () {
      it('allows HS256', function () {
        return provider.addClient({
          client_id: `${Math.random()}`,
          client_secret: 'its32bytes_____________________!',
          redirect_uris: ['https://client.example.com/cb'],
          [metadata]: 'HS256'
        });
      });

      it('allows HS384', function () {
        return provider.addClient({
          client_id: `${Math.random()}`,
          client_secret: 'its48bytes_____________________________________!',
          redirect_uris: ['https://client.example.com/cb'],
          [metadata]: 'HS384'
        });
      });

      it('allows HS512', function () {
        return provider.addClient({
          client_id: `${Math.random()}`,
          client_secret: 'its64bytes_____________________________________________________!',
          redirect_uris: ['https://client.example.com/cb'],
          [metadata]: 'HS512'
        });
      });
    });
  });
});
