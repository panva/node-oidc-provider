const Provider = require('../../lib');
const bootstrap = require('../test_helper');
const clientKey = require('../client.sig.key');
const uuid = require('uuid/v4');
const jose = require('node-jose');
const sinon = require('sinon');
const JWT = require('../../lib/helpers/jwt');
const { expect } = require('chai');

const route = '/token';

const tokenAuthSucceeded = {
  error: 'restricted_grant_type',
  error_description: 'requested grant type is restricted to this client',
};

const tokenAuthRejected = {
  error: 'invalid_client',
  error_description: 'client authentication failed',
};

function errorDetail(spy) {
  return spy.args[0][0].error_detail;
}

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

  it('expects auth to be provided', function () {
    return this.agent.post(route)
      .send({})
      .type('form')
      .expect(400)
      .expect({
        error: 'invalid_request',
        error_description: 'no client authentication mechanism provided',
      });
  });

  describe('none "auth"', () => {
    it('accepts the "auth"', function () {
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
          client_id: 'client-none',
        })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_request',
          error_description: 'implicit is not a grant resolved with a token endpoint call',
        });
    });

    it('rejects the "auth" if secret was also provided', function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
          client_id: 'client-none',
          client_secret: 'foobar',
        })
        .type('form')
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(errorDetail(spy)).to.equal('unexpected client_secret provided for token_endpoint_auth_method=none client request');
        })
        .expect(401)
        .expect(tokenAuthRejected);
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
        .expect(tokenAuthSucceeded);
    });

    it('accepts the auth even with id in the body', function () {
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
          client_id: 'client-basic',
        })
        .type('form')
        .auth('client-basic', 'secret')
        .expect(tokenAuthSucceeded);
    });

    it('rejects the auth when body id differs', function () {
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
          client_id: 'client-basic-other',
        })
        .type('form')
        .auth('client-basic', 'secret')
        .expect(400)
        .expect({
          error: 'invalid_request',
          error_description: 'mismatch in body and authorization client ids',
        });
    });

    it('accepts the auth (https://tools.ietf.org/html/rfc6749#appendix-B)', function () {
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
        })
        .type('form')
        .auth('+%25%26%2B%C2%A3%E2%82%AC', '+%25%26%2B%C2%A3%E2%82%AC')
        .expect(tokenAuthSucceeded);
    });

    it('accepts the auth (https://tools.ietf.org/html/rfc6749#appendix-B again)', function () {
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
        })
        .type('form')
        .auth('an%3Aidentifier', 'some+secure+%26+non-standard+secret')
        .expect(tokenAuthSucceeded);
    });

    it('accepts the auth (https://tools.ietf.org/html/rfc6749#appendix-B)', function () {
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
        })
        .type('form')
        .auth('foo with %', 'foo with $')
        .expect({
          error: 'invalid_request',
          error_description: 'client_id and client_secret are not properly encoded',
        });
    });

    it('validates the Basic scheme format (parts)', function () {
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
        })
        .type('form')
        .set('Authorization', 'Basic')
        .expect(400)
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
        .auth('foo', { type: 'bearer' })
        .expect(400)
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
        .expect(400)
        .expect({
          error: 'invalid_request',
          error_description: 'invalid authorization header value format',
        });
    });

    it('rejects invalid secrets', function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
        })
        .type('form')
        .auth('client-basic', 'invalid secret')
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(errorDetail(spy)).to.equal('invalid secret provided');
        })
        .expect(401)
        .expect(tokenAuthRejected);
    });

    it('rejects double auth', function () {
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
          client_id: 'client-basic',
          client_secret: 'secret',
        })
        .type('form')
        .auth('client-basic', 'invalid secret')
        .expect(400)
        .expect({
          error: 'invalid_request',
          error_description: 'client authentication must only be provided using one mechanism',
        });
    });

    it('rejects double auth (no client_id in body)', function () {
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
          client_secret: 'secret',
        })
        .type('form')
        .auth('client-basic', 'invalid secret')
        .expect(400)
        .expect({
          error: 'invalid_request',
          error_description: 'client authentication must only be provided using one mechanism',
        });
    });

    it('requires the client_secret to be sent', function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
        })
        .type('form')
        .auth('client-basic', '')
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(errorDetail(spy)).to.equal('client_secret must be provided in the Authorization header');
        })
        .expect(401)
        .expect(tokenAuthRejected);
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
        .expect(tokenAuthSucceeded);
    });

    it('rejects invalid secrets', function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
          client_id: 'client-post',
          client_secret: 'invalid',
        })
        .type('form')
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(errorDetail(spy)).to.equal('invalid secret provided');
        })
        .expect(401)
        .expect(tokenAuthRejected);
    });

    it('requires the client_secret to be sent', function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
          client_id: 'client-post',
          client_secret: '',
        })
        .type('form')
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(errorDetail(spy)).to.equal('client_secret must be provided in the body');
        })
        .expect(401)
        .expect(tokenAuthRejected);
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
        .expect(tokenAuthSucceeded));
    });

    it('rejects the auth if this is actually a none-client', function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);
      return JWT.sign({
        jti: uuid(),
        aud: this.provider.issuer + this.provider.pathFor('token'),
        sub: 'client-none',
        iss: 'client-none',
      }, this.key, 'HS256', { expiresIn: 60 }).then(assertion => this.agent.post(route)
        .send({
          client_id: 'client-none',
          client_assertion: assertion,
          grant_type: 'implicit',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect(401)
        .expect(tokenAuthRejected)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(errorDetail(spy)).to.equal('the registered client token_endpoint_auth_method does not match the provided auth mechanism');
        }));
    });

    it('rejects the auth if authorization header is also present', function () {
      return JWT.sign({
        jti: uuid(),
        aud: this.provider.issuer + this.provider.pathFor('token'),
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, this.key, 'HS256', { expiresIn: 60 }).then(assertion => this.agent.post(route)
        .auth('client-basic', 'secret')
        .send({
          client_assertion: assertion,
          grant_type: 'implicit',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_request',
          error_description: 'client authentication must only be provided using one mechanism',
        }));
    });

    it('rejects the auth if client secret is also present', function () {
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
          client_secret: 'foo',
        })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_request',
          error_description: 'client authentication must only be provided using one mechanism',
        }));
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
        .expect(tokenAuthSucceeded));
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
        .expect(400)
        .expect({
          error: 'invalid_request',
          error_description: 'invalid client_assertion format',
        });
    });

    it('exp must be set', function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);
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
        .expect(401)
        .expect(tokenAuthRejected)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(errorDetail(spy)).to.equal('expiration must be specified in the client_assertion JWT');
        }));
    });

    it('aud must be set', function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);
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
        .expect(401)
        .expect(tokenAuthRejected)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(errorDetail(spy)).to.equal('aud (JWT audience) must be provided in the client_assertion JWT');
        }));
    });

    it('jti must be set', function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);
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
        .expect(401)
        .expect(tokenAuthRejected)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(errorDetail(spy)).to.equal('unique jti (JWT ID) must be provided in the client_assertion JWT');
        }));
    });

    it('iss must be set', function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);
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
        .expect(401)
        .expect(tokenAuthRejected)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(errorDetail(spy)).to.equal('iss (JWT issuer) must be provided in the client_assertion JWT');
        }));
    });

    it('iss must be the client id', function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);
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
        .expect(401)
        .expect(tokenAuthRejected)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(errorDetail(spy)).to.equal('issuer (iss) must be the client id');
        }));
    });

    it('audience as array must contain the token endpoint', function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);
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
        .expect(401)
        .expect(tokenAuthRejected)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(errorDetail(spy)).to.equal('list of audience (aud) must include the endpoint url');
        }));
    });

    it('audience as single entry must be the token endpoint', function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);
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
        .expect(401)
        .expect(tokenAuthRejected)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(errorDetail(spy)).to.equal('audience (aud) must equal the endpoint url');
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
        .expect(400)
        .expect({
          error: 'invalid_request',
          error_description: 'subject of client_assertion must be the same as client_id provided in the body',
        }));
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
        .expect(400)
        .expect({
          error: 'invalid_request',
          error_description: 'client_assertion_type must be provided',
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
        .expect(400)
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
        .expect(400)
        .expect({
          error: 'invalid_request',
          error_description: 'invalid client_assertion format',
        });
    });

    it('rejects valid format and signature but expired/invalid jwts', function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);
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
        .expect(401)
        .expect(tokenAuthRejected)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(errorDetail(spy)).to.equal('jwt expired');
        }));
    });

    describe('JTI uniqueness', () => {
      it('reused jtis must be rejected', function () {
        const spy = sinon.spy();
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
              grant_type: 'implicit',
              client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            })
            .type('form')
            .expect(tokenAuthSucceeded)
            .then(() => {
              this.provider.once('grant.error', spy);
            })
            .then(() => this.agent.post(route)
              .send({
                client_assertion: assertion,
                grant_type: 'implicit',
                client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
              })
              .type('form')
              .expect(401)
              .expect(tokenAuthRejected)
              .expect(() => {
                expect(spy.calledOnce).to.be.true;
                expect(errorDetail(spy)).to.equal('jwt-bearer tokens must only be used once');
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
        const spy = sinon.spy();
        this.provider.once('grant.error', spy);
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
          .expect(401)
          .expect(tokenAuthRejected)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(errorDetail(spy)).to.equal('alg mismatch');
          }));
      });
    });
  });

  describe('private_key_jwt auth', () => {
    let privateKey;

    before(() => jose.JWK.asKey(clientKey).then((key) => {
      privateKey = key;
    }));

    after(function () {
      i(this.provider).configuration().clockTolerance = 0;
    });

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
        .expect(tokenAuthSucceeded));
    });

    it('accepts client assertions issued within acceptable system clock skew', function () {
      i(this.provider).configuration().clockTolerance = 10;
      return JWT.sign({
        jti: uuid(),
        aud: this.provider.issuer + this.provider.pathFor('token'),
        sub: 'client-jwt-key',
        iss: 'client-jwt-key',
        iat: Math.ceil(Date.now() / 1000) + 5,
      }, privateKey, 'RS256', {
        expiresIn: 60,
      }).then(assertion => this.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'implicit',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect(tokenAuthSucceeded));
    });
  });
});
