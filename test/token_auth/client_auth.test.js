const Provider = require('../../lib');
const bootstrap = require('../test_helper');
const clientKey = require('../client.sig.key');
const { v4: uuid } = require('uuid');
const jose = require('node-jose');
const JWT = require('../../lib/helpers/jwt');
const { expect } = require('chai');

const route = '/token';

describe('client authentication options', () => {
  before(bootstrap(__dirname)); // agent, this.provider, responses

  describe('discovery', () => {
    it('pushes no algs when neither _jwt method is enabled', () => {
      const provider = new Provider('http://localhost', {
        tokenEndpointAuthMethods: [
          'none',
          'client_secret_basic',
          'client_secret_post',
        ],
      });

      expect(i(provider).configuration('tokenEndpointAuthSigningAlgValues')).to.be.undefined;
      expect(i(provider).configuration('introspectionEndpointAuthSigningAlgValues')).to.be.undefined;
      expect(i(provider).configuration('revocationEndpointAuthSigningAlgValues')).to.be.undefined;
    });

    it('pushes only symmetric algs when client_secret_jwt is enabled', () => {
      const provider = new Provider('http://localhost', {
        tokenEndpointAuthMethods: [
          'none',
          'client_secret_basic',
          'client_secret_jwt',
          'client_secret_post',
        ],
      });

      const algs = [
        'HS256',
        'HS384',
        'HS512',
      ];

      expect(i(provider).configuration('tokenEndpointAuthSigningAlgValues')).to.eql(algs);
      expect(i(provider).configuration('introspectionEndpointAuthSigningAlgValues')).to.eql(algs);
      expect(i(provider).configuration('revocationEndpointAuthSigningAlgValues')).to.eql(algs);
    });

    it('pushes only asymmetric algs when private_key_jwt is enabled', () => {
      const provider = new Provider('http://localhost', {
        tokenEndpointAuthMethods: [
          'none',
          'client_secret_basic',
          'client_secret_post',
          'private_key_jwt',
        ],
      });

      const algs = [
        'RS256',
        'RS384',
        'RS512',
        'PS256',
        'PS384',
        'PS512',
        'ES256',
        'ES384',
        'ES512',
      ];

      expect(i(provider).configuration('tokenEndpointAuthSigningAlgValues')).to.eql(algs);
      expect(i(provider).configuration('introspectionEndpointAuthSigningAlgValues')).to.eql(algs);
      expect(i(provider).configuration('revocationEndpointAuthSigningAlgValues')).to.eql(algs);
    });

    it('pushes all algs when both _jwt methods are enabled', () => {
      const provider = new Provider('http://localhost', {
        tokenEndpointAuthMethods: [
          'none',
          'client_secret_basic',
          'client_secret_jwt',
          'client_secret_post',
          'private_key_jwt',
        ],
      });

      const algs = [
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
      ];

      expect(i(provider).configuration('tokenEndpointAuthSigningAlgValues')).to.eql(algs);
      expect(i(provider).configuration('introspectionEndpointAuthSigningAlgValues')).to.eql(algs);
      expect(i(provider).configuration('revocationEndpointAuthSigningAlgValues')).to.eql(algs);
    });
  });

  describe('none auth', () => {
    it('accepts the auth', function () {
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
          client_id: 'client-none',
        })
        .type('form')
        .expect({
          error: 'invalid_request',
          error_description: 'implicit is not a grant resolved with a token endpoint call',
        });
    });
  });

  describe('client_secret_basic auth', () => {
    it('accepts the auth', function () {
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
        })
        .type('form')
        .auth('client-basic', 'secret')
        .expect(this.responses.tokenAuthSucceeded);
    });

    it('validates the Basic scheme format (parts)', function () {
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
        })
        .type('form')
        .set('Authorization', 'Basic')
        .expect({
          error: 'invalid_request',
          error_description: 'invalid authorization header value format',
        });
    });

    it('validates the Basic scheme format (Basic)', function () {
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
        })
        .type('form')
        .set('Authorization', 'Bearer foo')
        .expect({
          error: 'invalid_request',
          error_description: 'invalid authorization header value format',
        });
    });

    it('validates the Basic scheme format (no :)', function () {
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
        })
        .type('form')
        .set('Authorization', 'Basic Zm9v')
        .expect({
          error: 'invalid_request',
          error_description: 'invalid authorization header value format',
        });
    });

    it('rejects invalid secrets', function () {
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
        })
        .type('form')
        .auth('client-basic', 'invalid secret')
        .expect(this.responses.tokenAuthRejected);
    });

    it('requires the client_secret to be sent', function () {
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
        })
        .type('form')
        .auth('client-basic', '')
        .expect({
          error: 'invalid_request',
          error_description: 'client_secret must be provided in the Authorization header',
        });
    });
  });

  describe('client_secret_post auth', () => {
    it('accepts the auth', function () {
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
          client_id: 'client-post',
          client_secret: 'secret',
        })
        .type('form')
        .expect(this.responses.tokenAuthSucceeded);
    });

    it('rejects the auth', function () {
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
          client_id: 'client-post',
          client_secret: 'invalid',
        })
        .type('form')
        .expect(this.responses.tokenAuthRejected);
    });

    it('requires the client_secret to be sent', function () {
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
          client_id: 'client-post',
          client_secret: '',
        })
        .type('form')
        .expect({
          error: 'invalid_request',
          error_description: 'client_secret must be provided in the body',
        });
    });
  });

  describe('client_secret_jwt auth', () => {
    before(async function () {
      this.key = (await this.provider.Client.find('client-jwt-secret')).keystore.get();
    });

    it('accepts the auth', function () {
      return JWT.sign({
        jti: uuid(),
        aud: this.provider.issuer + this.provider.pathFor('token'),
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, this.key, 'HS256', { expiresIn: 60 }).then(assertion => this.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'implicit',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect(this.responses.tokenAuthSucceeded));
    });

    it('accepts the auth when aud is an array', function () {
      return JWT.sign({
        jti: uuid(),
        aud: [this.provider.issuer + this.provider.pathFor('token')],
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, this.key, 'HS256', { expiresIn: 60 }).then(assertion => this.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'implicit',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
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
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
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
        exp: '',
      }, this.key, 'HS256', {
        // expiresIn: 60
      }).then(assertion => this.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'implicit',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect({
          error: 'invalid_request',
          error_description: 'expiration must be specified in the client_assertion JWT',
        }));
    });

    it('aud must be set', function () {
      return JWT.sign({
        jti: uuid(),
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, this.key, 'HS256', {
        expiresIn: 60,
      }).then(assertion => this.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'implicit',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect({
          error: 'invalid_request',
          error_description: 'aud (JWT audience) must be provided in the client_assertion JWT',
        }));
    });

    it('jti must be set', function () {
      return JWT.sign({
        // jti: uuid(),
        aud: this.provider.issuer + this.provider.pathFor('token'),
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, this.key, 'HS256', {
        expiresIn: 60,
      }).then(assertion => this.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'implicit',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
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
        expiresIn: 60,
      }).then(assertion => this.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'implicit',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
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
        expiresIn: 60,
      }).then(assertion => this.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'implicit',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
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
        expiresIn: 60,
      }).then(assertion => this.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'implicit',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
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
        expiresIn: 60,
      }).then(assertion => this.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'implicit',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect({
          error: 'invalid_request',
          error_description: 'audience (aud) must equal the endpoint url',
        }));
    });

    it('checks for mismatch in client_assertion client_id and body client_id', function () {
      return JWT.sign({
        jti: uuid(),
        aud: this.provider.issuer + this.provider.pathFor('token'),
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, this.key, 'HS256', { expiresIn: 60 }).then(assertion => this.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'implicit',
          client_id: 'mismatching-client-id',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect({
          error: 'invalid_request',
          error_description: 'subject of client_assertion must be the same as client_id',
        }));
    });

    it('requires client_assertion', function () {
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
          client_id: 'client-jwt-secret',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
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
        iss: 'client-jwt-secret',
      }, this.key, 'HS256', {
        expiresIn: 60,
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
        iss: 'client-jwt-secret',
      }, this.key, 'HS256', {
        expiresIn: 60,
      }).then(assertion => this.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'implicit',
          client_assertion_type: 'urn:ietf:mycustom',
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
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
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
        iss: 'client-jwt-secret',
      }, this.key, 'HS256', {
        expiresIn: -1,
      }).then(assertion => this.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'implicit',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect({
          error: 'invalid_client',
          error_description: 'client is invalid',
        }));
    });

    describe('JTI uniqueness', () => {
      it('reused jtis must be rejected', function () {
        return JWT.sign({
          jti: uuid(),
          aud: this.provider.issuer + this.provider.pathFor('token'),
          sub: 'client-jwt-secret',
          iss: 'client-jwt-secret',
        }, this.key, 'HS256', {
          expiresIn: 60,
        })
          .then(assertion => this.agent.post(route)
            .send({
              client_assertion: assertion,
              grant_type: 'authorization_code',
              code: 'foobar',
              redirect_uri: 'foobar',
              client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            })
            .type('form')
            .expect({
              error: 'invalid_grant',
              error_description: 'grant request is invalid',
            })
            .then(() => this.agent.post(route)
              .send({
                client_assertion: assertion,
                grant_type: 'authorization_code',
                code: 'foobar',
                redirect_uri: 'foobar',
                client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
              })
              .type('form')
              .expect({
                error: 'invalid_request',
                error_description: 'jwt-bearer tokens must only be used once',
              })));
      });
    });

    describe('when token_endpoint_auth_signing_alg is set on the client', () => {
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
          iss: 'client-jwt-secret',
        }, this.key, 'HS256', {
          expiresIn: 60,
        }).then(assertion => this.agent.post(route)
          .send({
            client_assertion: assertion,
            grant_type: 'implicit',
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          })
          .type('form')
          .expect({
            error: 'invalid_request',
            error_description: 'alg mismatch',
          }));
      });
    });
  });

  describe('private_key_jwt auth', () => {
    let privateKey;

    before(() => jose.JWK.asKey(clientKey).then((key) => {
      privateKey = key;
    }));

    it('accepts the auth', function () {
      return JWT.sign({
        jti: uuid(),
        aud: this.provider.issuer + this.provider.pathFor('token'),
        sub: 'client-jwt-key',
        iss: 'client-jwt-key',
      }, privateKey, 'RS256', {
        expiresIn: 60,
      }).then(assertion => this.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'implicit',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect(this.responses.tokenAuthSucceeded));
    });
  });
});
