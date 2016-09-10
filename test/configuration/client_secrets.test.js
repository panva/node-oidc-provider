'use strict';

const bootstrap = require('../test_helper');
const { expect } = require('chai');

describe('Provider#addClient', () => {
  const { provider } = bootstrap(__dirname);


  [
    'id_token_signed_response_alg',
    'request_object_signing_alg',
    'token_endpoint_auth_signing_alg',
    'userinfo_signed_response_alg'
  ].forEach((metadata) => {
    context(`configuring ${metadata} when secrets are not long enough`, () => {
      it('validates the secret length (HS256)', () => {
        return provider.addClient({
          client_id: `${Math.random()}`,
          client_secret: 'not32bytes_____________________',
          redirect_uris: ['https://client.example.com/cb'],
          [metadata]: 'HS256'
        }).then((client) => {
          expect(client).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err).to.have.property('message', 'invalid_client_metadata');
          expect(err).to.have.property('error_description', 'insufficient client_secret length');
        });
      });

      it('validates the secret length (HS384)', () => {
        return provider.addClient({
          client_id: `${Math.random()}`,
          client_secret: 'not48bytes_____________________________________',
          redirect_uris: ['https://client.example.com/cb'],
          [metadata]: 'HS384'
        }).then((client) => {
          expect(client).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err).to.have.property('message', 'invalid_client_metadata');
          expect(err).to.have.property('error_description', 'insufficient client_secret length');
        });
      });

      it('validates the secret length (HS512)', () => {
        return provider.addClient({
          client_id: `${Math.random()}`,
          client_secret: 'not64bytes_____________________________________________________',
          redirect_uris: ['https://client.example.com/cb'],
          [metadata]: 'HS512'
        }).then((client) => {
          expect(client).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err).to.have.property('message', 'invalid_client_metadata');
          expect(err).to.have.property('error_description', 'insufficient client_secret length');
        });
      });
    });

    context(`configuring ${metadata} when secrets are long enough`, () => {
      it('allows HS256', () => {
        return provider.addClient({
          client_id: `${Math.random()}`,
          client_secret: 'its32bytes_____________________!',
          redirect_uris: ['https://client.example.com/cb'],
          [metadata]: 'HS256'
        });
      });

      it('allows HS384', () => {
        return provider.addClient({
          client_id: `${Math.random()}`,
          client_secret: 'its48bytes_____________________________________!',
          redirect_uris: ['https://client.example.com/cb'],
          [metadata]: 'HS384'
        });
      });

      it('allows HS512', () => {
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
