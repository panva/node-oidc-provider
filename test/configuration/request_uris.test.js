'use strict';

const { expect } = require('chai');
const { Provider } = require('../../lib');

describe('client.requestUris', function () {
  it('defaults to empty array when registration of them is a must', function () {
    const provider = new Provider('http://localhost:3000', {
      subjectTypes: ['public'],
      features: {
        requestUri: { requireRequestUriRegistration: true }
      }
    });

    return provider.initialize({
      clients: [{
        client_id: 'client',
        client_secret: 'secret',
        id_token_signed_response_alg: 'none',
        redirect_uris: ['https://client.example.com/cb']
      }]
    }).then(() => provider.Client.find('client'))
    .then((client) => {
      expect(client).to.have.property('requestUris').that.is.an('array');
      expect(client.requestUris).to.be.empty;
    });
  });

  it('defaults to undefined when registration of them is not mandatory', function () {
    const provider = new Provider('http://localhost:3000', {
      subjectTypes: ['public'],
      features: {
        requestUri: { requireRequestUriRegistration: false }
      }
    });

    return provider.initialize({
      clients: [{
        client_id: 'client',
        client_secret: 'secret',
        id_token_signed_response_alg: 'none',
        redirect_uris: ['https://client.example.com/cb']
      }]
    }).then(() => provider.Client.find('client'))
    .then(client => expect(client.requestUris).to.be.undefined);
  });
});
