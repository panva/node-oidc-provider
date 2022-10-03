const { expect } = require('chai');

const { Provider } = require('../../lib');

describe('client.requestUris', () => {
  it('defaults to empty array when registration of them is a must', () => {
    const provider = new Provider('http://localhost:3000', {
      subjectTypes: ['public'],
      features: {
        requestObjects: { requestUri: true, requireUriRegistration: true },
      },
      clients: [{
        client_id: 'client',
        client_secret: 'secret',
        redirect_uris: ['https://client.example.com/cb'],
      }],
    });

    return provider.Client.find('client')
      .then((client) => {
        expect(client).to.have.property('requestUris').that.is.an('array');
        expect(client.requestUris).to.be.empty;
      });
  });

  it('defaults to undefined when registration of them is not mandatory', () => {
    const provider = new Provider('http://localhost:3000', {
      subjectTypes: ['public'],
      features: {
        requestObjects: { requestUri: true, requireUriRegistration: false },
      },
      clients: [{
        client_id: 'client',
        client_secret: 'secret',
        redirect_uris: ['https://client.example.com/cb'],
      }],
    });

    return provider.Client.find('client')
      .then((client) => expect(client.requestUris).to.be.undefined);
  });
});
