'use strict';

const { agent, provider, responses } = require('../test_helper')(__dirname);
const { v4: uuid } = require('node-uuid');
const route = '/token';
const JWT = require('../../lib/helpers/jwt');

describe('client_secret_basic auth', function() {
  const client = {
    token_endpoint_auth_method: 'client_secret_basic',
    client_id: 'client',
    client_secret: 'secret',
    redirect_uris: ['https://client.example.com/cb']
  };
  provider.setupClient(client);

  it('accepts the auth', function() {
    return agent.post(route)
      .send({
        grant_type: 'implicit'
      })
      .type('form')
      .auth(client.client_id, client.client_secret)
      .expect(responses.tokenAuthSucceeded);
  });
});

describe('client_secret_post auth', function() {
  const client = {
    token_endpoint_auth_method: 'client_secret_post',
    client_id: 'client',
    client_secret: 'secret',
    redirect_uris: ['https://client.example.com/cb']
  };
  provider.setupClient(client);

  it('accepts the auth', function() {
    return agent.post(route)
      .send({
        grant_type: 'implicit',
        client_id: client.client_id,
        client_secret: client.client_secret
      })
      .type('form')
      .expect(responses.tokenAuthSucceeded);
  });
});

describe('client_secret_jwt auth', function() {
  const client = {
    token_endpoint_auth_method: 'client_secret_jwt',
    client_id: 'client',
    client_secret: 'atleast32byteslongforHS256mmkay?',
    redirect_uris: ['https://client.example.com/cb']
  };
  provider.setupClient(client);

  it('accepts the auth', function() {
    let key = provider.Client.clients.client.keystore.get();
    return JWT.sign({
      jti: uuid(),
      aud: provider.issuer + provider.pathFor('token'),
      sub: client.client_id,
      iss: client.client_id
    }, key, 'HS256', {
      expiresIn: 60
    }).then((assertion) => {
      return agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'implicit',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        })
        .type('form')
        .expect(responses.tokenAuthSucceeded);
    });
  });
});

describe('private_key_jwt auth', function() {
  const client = {
    client_id: 'client',
    redirect_uris: ['https://client.example.com/cb'],
    token_endpoint_auth_method: 'private_key_jwt',
    jwks: {
      keys: [require('../client.sig.key')]
    }
  };
  provider.setupClient(client);

  it('accepts the auth', function() {
    let key = provider.Client.clients.client.keystore.get();

    return JWT.sign({
      jti: uuid(),
      aud: provider.issuer + provider.pathFor('token'),
      sub: client.client_id,
      iss: client.client_id
    }, key, 'RS256', {
      expiresIn: 60
    }).then((assertion) => {
      return agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'implicit',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        })
        .type('form')
        .expect(responses.tokenAuthSucceeded);
    });
  });
});
