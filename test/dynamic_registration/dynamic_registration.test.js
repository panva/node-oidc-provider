'use strict';

const { agent, provider } = require('../test_helper')(__dirname);
const { expect } = require('chai');

const Client = provider.get('Client');

provider.setupCerts();

function validateError(error) {
  const assert = error.exec ? 'match' : 'equal';
  return (response) => {
    expect(response.body.error).to[assert](error);
  };
}

function validateErrorDescription(description) {
  const assert = description.exec ? 'match' : 'equal';
  return (response) => {
    expect(response.body.error_description).to[assert](description);
  };
}

describe('registration features', function () {
  context('POST /reg', function () {
    it('generates the id, secret that does not expire and reg access token and returns the defaulted values', function () {
      return agent.post('/reg')
      .send({
        redirect_uris: ['https://client.example.com/cb']
      })
      .expect(201)
      .expect(function (response) {
        expect(response.body).to.contain.keys('client_id', 'client_secret', 'registration_access_token');
        expect(response.body).to.have.property('client_secret_expires_at', 0);
        expect(response.body).to.have.property('application_type', 'web');
        expect(response.body).to.have.property('id_token_signed_response_alg', 'RS256');
        expect(response.body).to.have.property('token_endpoint_auth_method', 'client_secret_basic');
        expect(response.body).to.have.property('require_auth_time', false);
        expect(response.body).to.have.property('grant_types').and.eql(['authorization_code']);
        expect(response.body).to.have.property('response_types').and.eql(['code']);
        expect(response.body).to.have.property('registration_client_uri', provider.issuer + '/reg/' + response.body.client_id); // eslint-disable-line prefer-template
      });
    });

    it('returns token-endpoint-like cache headers', function () {
      return agent.post('/reg')
      .send({
        redirect_uris: ['https://client.example.com/cb']
      })
      .expect('pragma', 'no-cache')
      .expect('cache-control', 'no-store');
    });

    it('stores the client using the provided adapter', function (done) {
      agent.post('/reg')
      .send({
        redirect_uris: ['https://client.example.com/cb']
      })
      .end(function (err, response) {
        if (err) return done(err);

        Client.purge(); // wipe the cache

        return Client.find(response.body.client_id)
        .then((client) => {
          expect(client).to.be.ok;
        })
        .then(done)
        .catch(done);
      });
    });

    it('validates the parameters to be valid and responds with errors', function () {
      return agent.post('/reg')
      .send({
        grant_types: ['this is clearly wrong'],
        redirect_uris: ['https://client.example.com/cb']
      })
      .expect(400)
      .expect(validateError('invalid_client_metadata'))
      .expect(validateErrorDescription(/grant_types/));
    });

    it('validates the parameters to be valid and responds with redirect_uri errors', function () {
      return agent.post('/reg')
      .send({
        // redirect_uris missing here
      })
      .expect(400)
      .expect(validateError('invalid_redirect_uri'))
      .expect(validateErrorDescription(/redirect_uris/));
    });

    it('only accepts application/json POSTs', function () {
      return agent.post('/reg')
      .send({
        redirect_uris: ['https://client.example.com/cb']
      })
      .type('form')
      .expect(400)
      .expect({
        error: 'invalid_request',
        error_description: 'only application/json content-type POST bodies are supported'
      });
    });
  });

  context('GET /reg/:clientId', function () {
    before(function () {
      return agent.post('/reg')
      .send({
        redirect_uris: ['https://client.example.com/cb']
      })
      .expect((response) => {
        this.clientId = response.body.client_id;
        this.token = response.body.registration_access_token;
        this.registrationResponse = response.body;
      });
    });

    it('returns all available nonsecret metadata', function () {
      return agent.get(`/reg/${this.clientId}`)
        .query({
          access_token: this.token
        })
        .expect(200)
        .expect('content-type', /application\/json/)
        .expect(function (response) {
          expect(response.body).to.contain.keys('client_id', 'client_secret', 'registration_access_token');
          expect(response.body).to.have.property('client_secret_expires_at', 0);
          expect(response.body).to.have.property('application_type', 'web');
          expect(response.body).to.have.property('id_token_signed_response_alg', 'RS256');
          expect(response.body).to.have.property('token_endpoint_auth_method', 'client_secret_basic');
          expect(response.body).to.have.property('require_auth_time', false);
          expect(response.body).to.have.property('grant_types').and.eql(['authorization_code']);
          expect(response.body).to.have.property('response_types').and.eql(['code']);
          expect(response.body).to.have.property('registration_client_uri', provider.issuer + '/reg/' + response.body.client_id); // eslint-disable-line prefer-template
        });
    });

    it('returns token-endpoint-like cache headers', function () {
      return agent.get(`/reg/${this.clientId}`)
        .query({
          access_token: this.token
        })
        .expect('pragma', 'no-cache')
        .expect('cache-control', 'no-store');
    });

    it('validates client is a valid client', function () {
      return agent.get('/reg/thisDOesnotCompute')
        .query({
          access_token: 'wahtever'
        })
        .expect(400)
        .expect(validateError('invalid_client'));
    });

    it('validates auth presence', function () {
      return agent.get(`/reg/${this.clientId}`)
        .expect(400)
        .expect(validateError('invalid_request'));
    });

    it('validates auth validity', function () {
      return agent.get(`/reg/${this.clientId}`)
        .query({
          access_token: 'invalid token'
        })
        .expect(401);
    });

    it('accepts query', function () {
      return agent.get(`/reg/${this.clientId}`)
        .query({
          access_token: this.token
        })
        .expect(200);
    });

    it('accepts header', function () {
      return agent.get(`/reg/${this.clientId}`)
        .set('Authorization', `Bearer ${this.token}`)
        .expect(200);
    });
  });
});
