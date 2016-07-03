'use strict';

const { agent, provider, responses } = require('../test_helper')(__dirname);
const { v4: uuid } = require('node-uuid');
const route = '/token';
const jose = require('node-jose');
const sinon = require('sinon');
const JWT = require('../../lib/helpers/jwt');
const Client = provider.get('Client');

describe('none auth', function () {
  provider.setupCerts();

  const client = {
    token_endpoint_auth_method: 'none',
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['implicit'],
    response_types: ['id_token'],
    redirect_uris: ['https://client.example.com/cb']
  };
  provider.setupClient(client);

  it('accepts the auth', function () {
    return agent.post(route)
      .send({
        grant_type: 'implicit'
      })
      .type('form')
      .auth(client.client_id, client.client_secret)
      .expect({
        error: 'invalid_request',
        error_description: 'client not supposed to access token endpoint',
      });
  });
});

describe('client_secret_basic auth', function () {
  const client = {
    token_endpoint_auth_method: 'client_secret_basic',
    client_id: 'client',
    client_secret: 'secret',
    redirect_uris: ['https://client.example.com/cb']
  };
  provider.setupClient(client);

  it('accepts the auth', function () {
    return agent.post(route)
      .send({
        grant_type: 'implicit'
      })
      .type('form')
      .auth(client.client_id, client.client_secret)
      .expect(responses.tokenAuthSucceeded);
  });

  it('rejects invalid secrets', function () {
    return agent.post(route)
      .send({
        grant_type: 'implicit'
      })
      .type('form')
      .auth(client.client_id, 'invalid secret')
      .expect(responses.tokenAuthRejected);
  });

  it('requires the client_secret to be sent', function () {
    return agent.post(route)
      .send({
        grant_type: 'implicit'
      })
      .type('form')
      .auth(client.client_id, '')
      .expect({
        error: 'invalid_request',
        error_description: 'client_secret must be provided in the Authorization header',
      });
  });
});

describe('client_secret_post auth', function () {
  const client = {
    token_endpoint_auth_method: 'client_secret_post',
    client_id: 'client',
    client_secret: 'secret',
    redirect_uris: ['https://client.example.com/cb']
  };
  provider.setupClient(client);

  it('accepts the auth', function () {
    return agent.post(route)
      .send({
        grant_type: 'implicit',
        client_id: client.client_id,
        client_secret: client.client_secret
      })
      .type('form')
      .expect(responses.tokenAuthSucceeded);
  });

  it('accepts the auth', function () {
    return agent.post(route)
      .send({
        grant_type: 'implicit',
        client_id: client.client_id,
        client_secret: 'invalid'
      })
      .type('form')
      .expect(responses.tokenAuthRejected);
  });

  it('requires the client_secret to be sent', function () {
    return agent.post(route)
      .send({
        grant_type: 'implicit',
        client_id: client.client_id,
        client_secret: ''
      })
      .type('form')
      .expect({
        error: 'invalid_request',
        error_description: 'client_secret must be provided in the body',
      });
  });
});

describe('client_secret_jwt auth', function () {
  const client = {
    token_endpoint_auth_method: 'client_secret_jwt',
    client_id: 'client',
    client_secret: 'atleast32byteslongforHS256mmkay?',
    redirect_uris: ['https://client.example.com/cb']
  };
  provider.setupClient(client);

  it('accepts the auth', function * () {
    const key = (yield Client.find('client')).keystore.get();
    return JWT.sign({
      jti: uuid(),
      aud: provider.issuer + provider.pathFor('token'),
      sub: client.client_id,
      iss: client.client_id
    }, key, 'HS256', {
      expiresIn: 60
    }).then((assertion) => agent.post(route)
      .send({
        client_assertion: assertion,
        grant_type: 'implicit',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      })
      .type('form')
      .expect(responses.tokenAuthSucceeded));
  });

  // TODO: it('rejects tokens signed wrong, invalid or expired');

  it('rejects malformed assertions', function () {
    return agent.post(route)
      .send({
        client_id: client.client_id,
        client_assertion: '.eyJzdWIiOiJjbGllbnQifQ.',
        grant_type: 'implicit',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      })
      .type('form')
      .expect({
        error: 'invalid_request',
        error_description: 'client_assertion could not be decoded',
      });
  });

  it('exp must be set', function * () {
    const key = (yield Client.find('client')).keystore.get();
    return JWT.sign({
      jti: uuid(),
      aud: provider.issuer + provider.pathFor('token'),
      sub: client.client_id,
      iss: client.client_id,
      exp: ''
    }, key, 'HS256', {
      // expiresIn: 60
    }).then((assertion) => agent.post(route)
      .send({
        client_assertion: assertion,
        grant_type: 'implicit',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      })
      .type('form')
      .expect({
        error: 'invalid_request',
        error_description: 'expiration must be specified in the client_assertion JWT',
      }));
  });

  it('jti must be set', function * () {
    const key = (yield Client.find('client')).keystore.get();
    return JWT.sign({
      // jti: uuid(),
      aud: provider.issuer + provider.pathFor('token'),
      sub: client.client_id,
      iss: client.client_id,
    }, key, 'HS256', {
      expiresIn: 60
    }).then((assertion) => agent.post(route)
      .send({
        client_assertion: assertion,
        grant_type: 'implicit',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      })
      .type('form')
      .expect({
        error: 'invalid_request',
        error_description: 'unique jti (JWT ID) must be provided in the client_assertion JWT',
      }));
  });

  it('iss must be set', function * () {
    const key = (yield Client.find('client')).keystore.get();
    return JWT.sign({
      jti: uuid(),
      aud: provider.issuer + provider.pathFor('token'),
      sub: client.client_id,
      // iss: client.client_id,
    }, key, 'HS256', {
      expiresIn: 60
    }).then((assertion) => agent.post(route)
      .send({
        client_assertion: assertion,
        grant_type: 'implicit',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      })
      .type('form')
      .expect({
        error: 'invalid_request',
        error_description: 'iss (JWT issuer) must be provided in the client_assertion JWT',
      }));
  });

  it('iss must be the client id', function * () {
    const key = (yield Client.find('client')).keystore.get();
    return JWT.sign({
      jti: uuid(),
      aud: provider.issuer + provider.pathFor('token'),
      sub: client.client_id,
      iss: 'not equal to clientid',
    }, key, 'HS256', {
      expiresIn: 60
    }).then((assertion) => agent.post(route)
      .send({
        client_assertion: assertion,
        grant_type: 'implicit',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      })
      .type('form')
      .expect({
        error: 'invalid_request',
        error_description: 'issuer (iss) must be the client id',
      }));
  });

  it('audience as array must contain the token endpoint', function * () {
    const key = (yield Client.find('client')).keystore.get();
    return JWT.sign({
      jti: uuid(),
      // aud: provider.issuer + provider.pathFor('token'),
      aud: ['misses the token endpoint'],
      sub: client.client_id,
      iss: client.client_id,
    }, key, 'HS256', {
      expiresIn: 60
    }).then((assertion) => agent.post(route)
      .send({
        client_assertion: assertion,
        grant_type: 'implicit',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      })
      .type('form')
      .expect({
        error: 'invalid_request',
        error_description: 'list of audience (aud) must include the token endpoint url',
      }));
  });

  it('audience as single entry must be the token endpoint', function * () {
    const key = (yield Client.find('client')).keystore.get();
    return JWT.sign({
      jti: uuid(),
      // aud: provider.issuer + provider.pathFor('token'),
      aud: 'not the token endpoint',
      sub: client.client_id,
      iss: client.client_id,
    }, key, 'HS256', {
      expiresIn: 60
    }).then((assertion) => agent.post(route)
      .send({
        client_assertion: assertion,
        grant_type: 'implicit',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      })
      .type('form')
      .expect({
        error: 'invalid_request',
        error_description: 'audience (aud) must equal the token endpoint url',
      }));
  });

  it('requires client_assertion', function () {
    return agent.post(route)
      .send({
        grant_type: 'implicit',
        client_id: client.client_id,
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      })
      .type('form')
      .expect({
        error: 'invalid_request',
        error_description: 'client_assertion must be provided',
      });
  });

  it('requires client_assertion_type', function * () {
    const key = (yield Client.find('client')).keystore.get();
    return JWT.sign({
      jti: uuid(),
      aud: provider.issuer + provider.pathFor('token'),
      sub: client.client_id,
      iss: client.client_id
    }, key, 'HS256', {
      expiresIn: 60
    }).then((assertion) => agent.post(route)
      .send({
        client_assertion: assertion,
        grant_type: 'implicit',
        // client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      })
      .type('form')
      .expect({
        error: 'invalid_request',
        error_description: 'client_assertion_type must have value urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      }));
  });

  it('requires client_assertion_type of specific value', function * () {
    const key = (yield Client.find('client')).keystore.get();
    return JWT.sign({
      jti: uuid(),
      aud: provider.issuer + provider.pathFor('token'),
      sub: client.client_id,
      iss: client.client_id
    }, key, 'HS256', {
      expiresIn: 60
    }).then((assertion) => agent.post(route)
      .send({
        client_assertion: assertion,
        grant_type: 'implicit',
        client_assertion_type: 'urn:ietf:mycustom'
      })
      .type('form')
      .expect({
        error: 'invalid_request',
        error_description: 'client_assertion_type must have value urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      }));
  });

  it('rejects invalid assertions', function () {
    return agent.post(route)
      .send({
        client_assertion: 'this.notatall.valid',
        grant_type: 'implicit',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      })
      .type('form')
      .expect({
        error: 'invalid_request',
        error_description: 'invalid client_assertion',
      });
  });

  it('rejects invalid jwts', function * () {
    const key = (yield Client.find('client')).keystore.get();
    return JWT.sign({
      jti: uuid(),
      aud: provider.issuer + provider.pathFor('token'),
      sub: client.client_id,
      iss: client.client_id
    }, key, 'HS256', {
      expiresIn: -1
    }).then((assertion) => agent.post(route)
      .send({
        client_assertion: assertion,
        grant_type: 'implicit',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      })
      .type('form')
      .expect({
        error: 'invalid_client',
        error_description: 'client is invalid',
      }));
  });

  describe('JTI uniqueness', function () {
    before(function () {
      sinon.stub(provider.configuration(), 'uniqueness', function () {
        return Promise.resolve(false);
      });
    });

    after(function () {
      provider.configuration().uniqueness.restore();
    });

    it('reused jtis must be rejected', function * () {
      const key = (yield Client.find('client')).keystore.get();
      return JWT.sign({
        jti: uuid(),
        aud: provider.issuer + provider.pathFor('token'),
        sub: client.client_id,
        iss: client.client_id
      }, key, 'HS256', {
        expiresIn: 60
      }).then((assertion) => agent.post(route)
      .send({
        client_assertion: assertion,
        grant_type: 'implicit',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      })
      .type('form')
      .expect({
        error: 'invalid_request',
        error_description: 'jwt-bearer tokens must only be used once',
      }));
    });
  });

  describe('when token_endpoint_auth_signing_alg is set on the client', function () {
    before(function * () {
      (yield Client.find('client')).tokenEndpointAuthSigningAlg = 'HS384';
    });
    after(function * () {
      delete (yield Client.find('client')).tokenEndpointAuthSigningAlg;
    });
    it('rejects signatures with different algorithm', function * () {
      const key = (yield Client.find('client')).keystore.get();
      return JWT.sign({
        jti: uuid(),
        aud: provider.issuer + provider.pathFor('token'),
        sub: client.client_id,
        iss: client.client_id
      }, key, 'HS256', {
        expiresIn: 60
      }).then((assertion) => agent.post(route)
      .send({
        client_assertion: assertion,
        grant_type: 'implicit',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      })
      .type('form')
      .expect({
        error: 'invalid_request',
        error_description: 'alg mismatch',
      }));
    });
  });
});

const clientKey = require('../client.sig.key');

describe('private_key_jwt auth', function () {
  let privateKey;

  before(function () {
    return jose.JWK.asKey(clientKey).then(function (key) {
      privateKey = key;
    });
  });

  const client = {
    client_id: 'client',
    client_secret: 'whateverwontbeusedanyway',
    redirect_uris: ['https://client.example.com/cb'],
    token_endpoint_auth_method: 'private_key_jwt',
    jwks: {
      keys: [clientKey]
    }
  };
  provider.setupClient(client);

  it('accepts the auth', function () {
    return JWT.sign({
      jti: uuid(),
      aud: provider.issuer + provider.pathFor('token'),
      sub: client.client_id,
      iss: client.client_id
    }, privateKey, 'RS256', {
      expiresIn: 60
    }).then((assertion) => agent.post(route)
      .send({
        client_assertion: assertion,
        grant_type: 'implicit',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      })
      .type('form')
      .expect(responses.tokenAuthSucceeded));
  });
});
