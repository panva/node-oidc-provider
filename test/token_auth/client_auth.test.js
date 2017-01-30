'use strict';

const Provider = require('../../lib');
const bootstrap = require('../test_helper');
const clientKey = require('../client.sig.key');
const { v4: uuid } = require('uuid');
const jose = require('node-jose');
const JWT = require('../../lib/helpers/jwt');
const { expect } = require('chai');

const route = '/token';

describe('client authentication options', function () {
  before(bootstrap(__dirname)); // agent, this.provider, responses

  describe('discovery', function () {
    it('pushes no algs when neither _jwt method is enabled', function () {
      const provider = new Provider('http://localhost', {
        tokenEndpointAuthMethods: [
          'none',
          'client_secret_basic',
          'client_secret_post',
        ],
      });

      expect(i(provider).configuration('tokenEndpointAuthSigningAlgValues')).to.be.undefined;
    });

    it('pushes only symmetric algs when client_secret_jwt is enabled', function () {
      const provider = new Provider('http://localhost', {
        tokenEndpointAuthMethods: [
          'none',
          'client_secret_basic',
          'client_secret_jwt',
          'client_secret_post',
        ],
      });

      expect(i(provider).configuration('tokenEndpointAuthSigningAlgValues')).to.eql([
        'HS256',
        'HS384',
        'HS512',
      ]);
    });

    it('pushes only asymmetric algs when private_key_jwt is enabled', function () {
      const provider = new Provider('http://localhost', {
        tokenEndpointAuthMethods: [
          'none',
          'client_secret_basic',
          'client_secret_post',
          'private_key_jwt',
        ],
      });

      expect(i(provider).configuration('tokenEndpointAuthSigningAlgValues')).to.eql([
        'RS256',
        'RS384',
        'RS512',
        'PS256',
        'PS384',
        'PS512',
        'ES256',
        'ES384',
        'ES512',
      ]);
    });

    it('pushes all algs when both _jwt methods are enabled', function () {
      const provider = new Provider('http://localhost', {
        tokenEndpointAuthMethods: [
          'none',
          'client_secret_basic',
          'client_secret_jwt',
          'client_secret_post',
          'private_key_jwt',
        ],
      });

      expect(i(provider).configuration('tokenEndpointAuthSigningAlgValues')).to.eql([
        'HS256',
        'HS384',
        'HS512',
        'RS256',
        'RS384',
        'RS512',
        'PS256',
        'PS384',
        'PS512',
        'ES256',
        'ES384',
        'ES512',
      ]);
    });
  });

  describe('none auth', function () {
    it('accepts the auth', function () {
      return this.agent.post(route)
      .send({
        grant_type: 'implicit'
      })
      .type('form')
      .auth('client-none', 'secret')
      .expect({
        error: 'invalid_request',
        error_description: 'client not supposed to access token endpoint',
      });
    });
  });

  describe('client_secret_basic auth', function () {
    it('accepts the auth', function () {
      return this.agent.post(route)
      .send({
        grant_type: 'implicit'
      })
      .type('form')
      .auth('client-basic', 'secret')
      .expect(this.responses.tokenAuthSucceeded);
    });

    it('rejects invalid secrets', function () {
      return this.agent.post(route)
      .send({
        grant_type: 'implicit'
      })
      .type('form')
      .auth('client-basic', 'invalid secret')
      .expect(this.responses.tokenAuthRejected);
    });

    it('requires the client_secret to be sent', function () {
      return this.agent.post(route)
      .send({
        grant_type: 'implicit'
      })
      .type('form')
      .auth('client-basic', '')
      .expect({
        error: 'invalid_request',
        error_description: 'client_secret must be provided in the Authorization header',
      });
    });
  });

  describe('client_secret_post auth', function () {
    it('accepts the auth', function () {
      return this.agent.post(route)
      .send({
        grant_type: 'implicit',
        client_id: 'client-post',
        client_secret: 'secret'
      })
      .type('form')
      .expect(this.responses.tokenAuthSucceeded);
    });

    it('rejects the auth', function () {
      return this.agent.post(route)
      .send({
        grant_type: 'implicit',
        client_id: 'client-post',
        client_secret: 'invalid'
      })
      .type('form')
      .expect(this.responses.tokenAuthRejected);
    });

    it('requires the client_secret to be sent', function () {
      return this.agent.post(route)
      .send({
        grant_type: 'implicit',
        client_id: 'client-post',
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
    before(async function () {
      this.key = (await this.provider.Client.find('client-jwt-secret')).keystore.get();
    });

    it('accepts the auth', function () {
      return JWT.sign({
        jti: uuid(),
        aud: this.provider.issuer + this.provider.pathFor('token'),
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret'
      }, this.key, 'HS256', { expiresIn: 60 }).then(assertion => this.agent.post(route)
      .send({
        client_assertion: assertion,
        grant_type: 'implicit',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      })
      .type('form')
      .expect(this.responses.tokenAuthSucceeded));
    });

    it('rejects malformed assertions', function () {
      return this.agent.post(route)
      .send({
        client_id: 'client-jwt-secret',
        client_assertion: '.eyJzdWIiOiJjbGllbnQtand0LXNlY3JldCIsImFsZyI6IkhTMjU2In0.',
        grant_type: 'implicit',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      })
      .type('form')
      .expect({
        error: 'invalid_request',
        error_description: 'client_assertion could not be decoded',
      });
    });

    it('exp must be set', function () {
      return JWT.sign({
        jti: uuid(),
        aud: this.provider.issuer + this.provider.pathFor('token'),
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
        exp: ''
      }, this.key, 'HS256', {
        // expiresIn: 60
      }).then(assertion => this.agent.post(route)
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

    it('jti must be set', function () {
      return JWT.sign({
        // jti: uuid(),
        aud: this.provider.issuer + this.provider.pathFor('token'),
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, this.key, 'HS256', {
        expiresIn: 60
      }).then(assertion => this.agent.post(route)
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

    it('iss must be set', function () {
      return JWT.sign({
        jti: uuid(),
        aud: this.provider.issuer + this.provider.pathFor('token'),
        sub: 'client-jwt-secret',
        // iss: 'client-jwt-secret',
      }, this.key, 'HS256', {
        expiresIn: 60
      }).then(assertion => this.agent.post(route)
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

    it('iss must be the client id', function () {
      return JWT.sign({
        jti: uuid(),
        aud: this.provider.issuer + this.provider.pathFor('token'),
        sub: 'client-jwt-secret',
        iss: 'not equal to clientid',
      }, this.key, 'HS256', {
        expiresIn: 60
      }).then(assertion => this.agent.post(route)
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

    it('audience as array must contain the token endpoint', function () {
      return JWT.sign({
        jti: uuid(),
        // aud: this.provider.issuer + this.provider.pathFor('token'),
        aud: ['misses the token endpoint'],
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, this.key, 'HS256', {
        expiresIn: 60
      }).then(assertion => this.agent.post(route)
      .send({
        client_assertion: assertion,
        grant_type: 'implicit',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      })
      .type('form')
      .expect({
        error: 'invalid_request',
        error_description: 'list of audience (aud) must include the endpoint url',
      }));
    });

    it('audience as single entry must be the token endpoint', function () {
      return JWT.sign({
        jti: uuid(),
        // aud: this.provider.issuer + this.provider.pathFor('token'),
        aud: 'not the token endpoint',
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, this.key, 'HS256', {
        expiresIn: 60
      }).then(assertion => this.agent.post(route)
      .send({
        client_assertion: assertion,
        grant_type: 'implicit',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      })
      .type('form')
      .expect({
        error: 'invalid_request',
        error_description: 'audience (aud) must equal the endpoint url',
      }));
    });

    it('requires client_assertion', function () {
      return this.agent.post(route)
      .send({
        grant_type: 'implicit',
        client_id: 'client-jwt-secret',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      })
      .type('form')
      .expect({
        error: 'invalid_request',
        error_description: 'client_assertion must be provided',
      });
    });

    it('requires client_assertion_type', function () {
      return JWT.sign({
        jti: uuid(),
        aud: this.provider.issuer + this.provider.pathFor('token'),
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret'
      }, this.key, 'HS256', {
        expiresIn: 60
      }).then(assertion => this.agent.post(route)
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

    it('requires client_assertion_type of specific value', function () {
      return JWT.sign({
        jti: uuid(),
        aud: this.provider.issuer + this.provider.pathFor('token'),
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret'
      }, this.key, 'HS256', {
        expiresIn: 60
      }).then(assertion => this.agent.post(route)
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
      return this.agent.post(route)
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

    it('rejects invalid jwts', function () {
      return JWT.sign({
        jti: uuid(),
        aud: this.provider.issuer + this.provider.pathFor('token'),
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret'
      }, this.key, 'HS256', {
        expiresIn: -1
      }).then(assertion => this.agent.post(route)
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
      it('reused jtis must be rejected', function () {
        return JWT.sign({
          jti: uuid(),
          aud: this.provider.issuer + this.provider.pathFor('token'),
          sub: 'client-jwt-secret',
          iss: 'client-jwt-secret'
        }, this.key, 'HS256', {
          expiresIn: 60
        })
        .then((assertion) => {
          return this.agent.post(route)
          .send({
            client_assertion: assertion,
            grant_type: 'authorization_code',
            code: 'foobar',
            redirect_uri: 'foobar',
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
          })
          .type('form')
          .expect({
            error: 'invalid_token',
            error_description: 'invalid token provided',
          })
          .then(() => {
            return this.agent.post(route)
            .send({
              client_assertion: assertion,
              grant_type: 'authorization_code',
              code: 'foobar',
              redirect_uri: 'foobar',
              client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            })
            .type('form')
            .expect({
              error: 'invalid_request',
              error_description: 'jwt-bearer tokens must only be used once',
            });
          });
        });
      });
    });

    describe('when token_endpoint_auth_signing_alg is set on the client', function () {
      before(async function () {
        (await this.provider.Client.find('client-jwt-secret')).tokenEndpointAuthSigningAlg = 'HS384';
      });
      after(async function () {
        delete (await this.provider.Client.find('client-jwt-secret')).tokenEndpointAuthSigningAlg;
      });
      it('rejects signatures with different algorithm', function () {
        return JWT.sign({
          jti: uuid(),
          aud: this.provider.issuer + this.provider.pathFor('token'),
          sub: 'client-jwt-secret',
          iss: 'client-jwt-secret'
        }, this.key, 'HS256', {
          expiresIn: 60
        }).then(assertion => this.agent.post(route)
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

  describe('private_key_jwt auth', function () {
    let privateKey;

    before(function () {
      return jose.JWK.asKey(clientKey).then((key) => {
        privateKey = key;
      });
    });

    it('accepts the auth', function () {
      return JWT.sign({
        jti: uuid(),
        aud: this.provider.issuer + this.provider.pathFor('token'),
        sub: 'client-jwt-key',
        iss: 'client-jwt-key'
      }, privateKey, 'RS256', {
        expiresIn: 60
      }).then(assertion => this.agent.post(route)
      .send({
        client_assertion: assertion,
        grant_type: 'implicit',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      })
      .type('form')
      .expect(this.responses.tokenAuthSucceeded));
    });
  });
});
