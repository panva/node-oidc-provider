const { readFileSync } = require('fs');

const got = require('got');
const nock = require('nock');
const jose = require('jose');
const sinon = require('sinon');
const { expect } = require('chai');
const cloneDeep = require('lodash/cloneDeep');

const runtimeSupport = require('../../lib/helpers/runtime_support');
const nanoid = require('../../lib/helpers/nanoid');
const { Provider } = require('../../lib');
const bootstrap = require('../test_helper');
const clientKey = require('../client.sig.key');
const JWT = require('../../lib/helpers/jwt');
const { JWA } = require('../../lib/consts');
const mtlsKeys = require('../jwks/jwks.json');

const rsacrt = readFileSync('test/jwks/rsa.crt').toString();
const eccrt = readFileSync('test/jwks/ec.crt').toString();

const route = '/token';

const tokenAuthSucceeded = {
  error: 'unauthorized_client',
  error_description: 'requested grant type is not allowed for this client',
};

const introspectionAuthSucceeded = {
  active: false,
};

const tokenAuthRejected = {
  error: 'invalid_client',
  error_description: 'client authentication failed',
};

function errorDetail(spy) {
  return spy.args[0][1].error_detail;
}

describe('client authentication options', () => {
  before(bootstrap(__dirname));

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
        whitelistedJWA: cloneDeep(JWA),
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
        whitelistedJWA: cloneDeep(JWA),
      });

      const algs = [
        'RS256',
        'RS384',
        'RS512',
        'PS256',
        'PS384',
        'PS512',
        'ES256',
        'ES256K',
        'ES384',
        'ES512',
        runtimeSupport.EdDSA ? 'EdDSA' : false,
      ].filter(Boolean);

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
        whitelistedJWA: cloneDeep(JWA),
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
        'ES256K',
        'ES384',
        'ES512',
        runtimeSupport.EdDSA ? 'EdDSA' : false,
      ].filter(Boolean);

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

  it('rejects when no client is found', function () {
    return this.agent.post(route)
      .send({
        grant_type: 'implicit',
        client_id: 'client-not-found',
      })
      .type('form')
      .expect(401)
      .expect(tokenAuthRejected);
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
          expect(errorDetail(spy)).to.equal('the registered client token_endpoint_auth_method does not match the provided auth mechanism');
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

    it('accepts the auth (but client configured with post)', function () {
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
        })
        .type('form')
        .auth('client-post', 'secret')
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

    it('rejects improperly encoded headers', function () {
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
        })
        .type('form')
        .auth('foo with %', 'foo with $')
        .expect({
          error: 'invalid_request',
          error_description: 'client_id and client_secret in the authorization header are not properly encoded',
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
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
        })
        .type('form')
        .auth('client-basic', '')
        .expect(400)
        .expect({
          error: 'invalid_request',
          error_description: 'client_secret must be provided in the Authorization header',
        });
    });

    it('rejects expired secrets', function () {
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
        })
        .type('form')
        .auth('secret-expired-basic', 'secret')
        .expect(400)
        .expect({
          error: 'invalid_client',
          error_description: 'could not authenticate the client - its client secret is expired',
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
        .expect(tokenAuthSucceeded);
    });

    // TODO: not sure why when mounted everything crap out
    if (!process.env.MOUNT_VIA) {
      it('can use transfer-encoding: chunked', async () => {
        const { address, port } = global.server.address();

        const response = await got.post(`http://[${address}]:${port}${route}`, {
          throwHttpErrors: false,
          form: true,
          body: {
            grant_type: 'implicit',
            client_id: 'client-post',
            client_secret: 'secret',
          },
          headers: { 'transfer-encoding': 'chunked' },
        });

        expect(JSON.parse(response.body)).to.deep.eql(tokenAuthSucceeded);
      });
    }

    it('accepts the auth (but client configured with basic)', function () {
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
          client_id: 'client-basic',
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
          expect(errorDetail(spy)).to.equal('the registered client token_endpoint_auth_method does not match the provided auth mechanism');
        })
        .expect(401)
        .expect(tokenAuthRejected);
    });

    it('rejects expired secrets', function () {
      return this.agent.post(route)
        .send({
          grant_type: 'implicit',
          client_id: 'secret-expired-basic',
          client_secret: 'secret',
        })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_client',
          error_description: 'could not authenticate the client - its client secret is expired',
        });
    });
  });

  describe('client_secret_jwt auth', () => {
    before(async function () {
      this.key = (await this.provider.Client.find('client-jwt-secret')).keystore.get({ alg: 'HS256' });
    });

    it('accepts the auth', function () {
      return JWT.sign({
        jti: nanoid(),
        aud: this.provider.issuer + this.suitePath('/token'),
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, this.key, 'HS256', { expiresIn: 60 }).then((assertion) => this.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'implicit',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect(tokenAuthSucceeded));
    });

    describe('audience', () => {
      it('accepts the auth (issuer as aud)', function () {
        return JWT.sign({
          jti: nanoid(),
          aud: this.provider.issuer,
          sub: 'client-jwt-secret',
          iss: 'client-jwt-secret',
        }, this.key, 'HS256', { expiresIn: 60 }).then((assertion) => this.agent.post(route)
          .send({
            client_assertion: assertion,
            grant_type: 'implicit',
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          })
          .type('form')
          .expect(tokenAuthSucceeded));
      });

      it('accepts the auth (endpoint URL as aud)', function () {
        return JWT.sign({
          jti: nanoid(),
          aud: this.provider.issuer + this.suitePath('/token/introspection'),
          sub: 'client-jwt-secret',
          iss: 'client-jwt-secret',
        }, this.key, 'HS256', { expiresIn: 60 }).then((assertion) => this.agent.post('/token/introspection')
          .send({
            client_assertion: assertion,
            token: 'foo',
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          })
          .type('form')
          .expect(introspectionAuthSucceeded));
      });

      it('accepts the auth (token endpoint URL as aud)', function () {
        return JWT.sign({
          jti: nanoid(),
          aud: this.provider.issuer + this.suitePath('/token'),
          sub: 'client-jwt-secret',
          iss: 'client-jwt-secret',
        }, this.key, 'HS256', { expiresIn: 60 }).then((assertion) => this.agent.post('/token/introspection')
          .send({
            client_assertion: assertion,
            token: 'foo',
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          })
          .type('form')
          .expect(introspectionAuthSucceeded));
      });

      it('accepts the auth (issuer as [aud])', function () {
        return JWT.sign({
          jti: nanoid(),
          aud: [this.provider.issuer],
          sub: 'client-jwt-secret',
          iss: 'client-jwt-secret',
        }, this.key, 'HS256', { expiresIn: 60 }).then((assertion) => this.agent.post(route)
          .send({
            client_assertion: assertion,
            grant_type: 'implicit',
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          })
          .type('form')
          .expect(tokenAuthSucceeded));
      });

      it('accepts the auth (endpoint URL as [aud])', function () {
        return JWT.sign({
          jti: nanoid(),
          aud: [this.provider.issuer + this.suitePath('/token/introspection')],
          sub: 'client-jwt-secret',
          iss: 'client-jwt-secret',
        }, this.key, 'HS256', { expiresIn: 60 }).then((assertion) => this.agent.post('/token/introspection')
          .send({
            client_assertion: assertion,
            token: 'foo',
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          })
          .type('form')
          .expect(introspectionAuthSucceeded));
      });

      it('accepts the auth (token endpoint URL as [aud])', function () {
        return JWT.sign({
          jti: nanoid(),
          aud: [this.provider.issuer + this.suitePath('/token')],
          sub: 'client-jwt-secret',
          iss: 'client-jwt-secret',
        }, this.key, 'HS256', { expiresIn: 60 }).then((assertion) => this.agent.post('/token/introspection')
          .send({
            client_assertion: assertion,
            token: 'foo',
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          })
          .type('form')
          .expect(introspectionAuthSucceeded));
      });
    });

    it('rejects the auth if this is actually a none-client', function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);
      return JWT.sign({
        jti: nanoid(),
        aud: this.provider.issuer + this.suitePath('/token'),
        sub: 'client-none',
        iss: 'client-none',
      }, this.key, 'HS256', { expiresIn: 60 }).then((assertion) => this.agent.post(route)
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
        jti: nanoid(),
        aud: this.provider.issuer + this.suitePath('/token'),
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, this.key, 'HS256', { expiresIn: 60 }).then((assertion) => this.agent.post(route)
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
        jti: nanoid(),
        aud: this.provider.issuer + this.suitePath('/token'),
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, this.key, 'HS256', { expiresIn: 60 }).then((assertion) => this.agent.post(route)
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
        jti: nanoid(),
        aud: [this.provider.issuer + this.suitePath('/token')],
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, this.key, 'HS256', { expiresIn: 60 }).then((assertion) => this.agent.post(route)
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
        jti: nanoid(),
        aud: this.provider.issuer + this.suitePath('/token'),
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
        exp: '',
      }, this.key, 'HS256', {
        // expiresIn: 60
      }).then((assertion) => this.agent.post(route)
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
        jti: nanoid(),
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, this.key, 'HS256', {
        expiresIn: 60,
      }).then((assertion) => this.agent.post(route)
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
        // jti: nanoid(),
        aud: this.provider.issuer + this.suitePath('/token'),
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, this.key, 'HS256', {
        expiresIn: 60,
      }).then((assertion) => this.agent.post(route)
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
        jti: nanoid(),
        aud: this.provider.issuer + this.suitePath('/token'),
        sub: 'client-jwt-secret',
        // iss: 'client-jwt-secret',
      }, this.key, 'HS256', {
        expiresIn: 60,
      }).then((assertion) => this.agent.post(route)
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
        jti: nanoid(),
        aud: this.provider.issuer + this.suitePath('/token'),
        sub: 'client-jwt-secret',
        iss: 'not equal to clientid',
      }, this.key, 'HS256', {
        expiresIn: 60,
      }).then((assertion) => this.agent.post(route)
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
        jti: nanoid(),
        // aud: this.provider.issuer + this.suitePath('/token'),
        aud: ['misses the token endpoint'],
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, this.key, 'HS256', {
        expiresIn: 60,
      }).then((assertion) => this.agent.post(route)
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
          expect(errorDetail(spy)).to.equal('list of audience (aud) must include the endpoint url, issuer identifier or token endpoint url');
        }));
    });

    it('audience as single entry must be the token endpoint', function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);
      return JWT.sign({
        jti: nanoid(),
        // aud: this.provider.issuer + this.suitePath('/token'),
        aud: 'not the token endpoint',
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, this.key, 'HS256', {
        expiresIn: 60,
      }).then((assertion) => this.agent.post(route)
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
          expect(errorDetail(spy)).to.equal('audience (aud) must equal the endpoint url, issuer identifier or token endpoint url');
        }));
    });

    it('checks for mismatch in client_assertion client_id and body client_id', function () {
      return JWT.sign({
        jti: nanoid(),
        aud: this.provider.issuer + this.suitePath('/token'),
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, this.key, 'HS256', { expiresIn: 60 }).then((assertion) => this.agent.post(route)
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
        jti: nanoid(),
        aud: this.provider.issuer + this.suitePath('/token'),
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, this.key, 'HS256', {
        expiresIn: 60,
      }).then((assertion) => this.agent.post(route)
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
        jti: nanoid(),
        aud: this.provider.issuer + this.suitePath('/token'),
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, this.key, 'HS256', {
        expiresIn: 60,
      }).then((assertion) => this.agent.post(route)
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
        jti: nanoid(),
        aud: this.provider.issuer + this.suitePath('/token'),
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, this.key, 'HS256', {
        expiresIn: -1,
      }).then((assertion) => this.agent.post(route)
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

    it('rejects assertions when the secret is expired', async function () {
      const key = (await this.provider.Client.find('secret-expired-jwt')).keystore.get({ alg: 'HS256' });
      return JWT.sign({
        jti: nanoid(),
        aud: this.provider.issuer + this.suitePath('/token'),
        sub: 'secret-expired-jwt',
        iss: 'secret-expired-jwt',
      }, key, 'HS256', {
        expiresIn: -1,
      }).then((assertion) => this.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'implicit',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_client',
          error_description: 'could not authenticate the client - its client secret used for the client_assertion is expired',
        }));
    });

    describe('JTI uniqueness', () => {
      it('reused jtis must be rejected', function () {
        const spy = sinon.spy();
        return JWT.sign({
          jti: nanoid(),
          aud: this.provider.issuer + this.suitePath('/token'),
          sub: 'client-jwt-secret',
          iss: 'client-jwt-secret',
        }, this.key, 'HS256', {
          expiresIn: 60,
        })
          .then((assertion) => this.agent.post(route)
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
                expect(errorDetail(spy)).to.equal('client assertion tokens must only be used once');
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
          jti: nanoid(),
          aud: this.provider.issuer + this.suitePath('/token'),
          sub: 'client-jwt-secret',
          iss: 'client-jwt-secret',
        }, this.key, 'HS256', {
          expiresIn: 60,
        }).then((assertion) => this.agent.post(route)
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

    before(() => {
      privateKey = jose.JWK.asKey(clientKey);
    });

    after(function () {
      i(this.provider).configuration().clockTolerance = 0;
    });

    it('accepts the auth', function () {
      return JWT.sign({
        jti: nanoid(),
        aud: this.provider.issuer + this.suitePath('/token'),
        sub: 'client-jwt-key',
        iss: 'client-jwt-key',
      }, privateKey, 'RS256', {
        expiresIn: 60,
      }).then((assertion) => this.agent.post(route)
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
        jti: nanoid(),
        aud: this.provider.issuer + this.suitePath('/token'),
        sub: 'client-jwt-key',
        iss: 'client-jwt-key',
        iat: Math.ceil(Date.now() / 1000) + 5,
      }, privateKey, 'RS256', {
        expiresIn: 60,
      }).then((assertion) => this.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'implicit',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect(tokenAuthSucceeded));
    });
  });

  if (runtimeSupport.KeyObject) {
    describe('tls_client_auth auth', () => {
      it('accepts the auth', function () {
        return this.agent.post(route)
          .set('x-ssl-client-cert', rsacrt.replace(RegExp('\\r?\\n', 'g'), ''))
          .set('x-ssl-client-verify', 'SUCCESS')
          .set('x-ssl-client-san-dns', 'rp.example.com')
          .send({
            client_id: 'client-pki-mtls',
            grant_type: 'implicit',
          })
          .type('form')
          .expect(tokenAuthSucceeded);
      });

      it('fails the auth when getCertificate() does not return a cert', function () {
        return this.agent.post(route)
          .send({
            client_id: 'client-pki-mtls',
            grant_type: 'implicit',
          })
          .type('form')
          .expect(tokenAuthRejected);
      });

      it('fails the auth when certificateAuthorized() fails', function () {
        return this.agent.post(route)
          .set('x-ssl-client-cert', rsacrt.replace(RegExp('\\r?\\n', 'g'), ''))
          .set('x-ssl-client-verify', 'FAILED: self signed certificate')
          .set('x-ssl-client-san-dns', 'rp.example.com')
          .send({
            client_id: 'client-pki-mtls',
            grant_type: 'implicit',
          })
          .type('form')
          .expect(tokenAuthRejected);
      });

      it('fails the auth when certificateSubjectMatches() return false', function () {
        return this.agent.post(route)
          .set('x-ssl-client-cert', rsacrt.replace(RegExp('\\r?\\n', 'g'), ''))
          .set('x-ssl-client-verify', 'SUCCESS')
          .set('x-ssl-client-san-dns', 'foobarbaz')
          .send({
            client_id: 'client-pki-mtls',
            grant_type: 'implicit',
          })
          .type('form')
          .expect(tokenAuthRejected);
      });
    });

    describe('self_signed_tls_client_auth auth', () => {
      it('accepts the auth [1/2]', function () {
        return this.agent.post(route)
          .set('x-ssl-client-cert', rsacrt.replace(RegExp('\\r?\\n', 'g'), ''))
          .send({
            client_id: 'client-self-signed-mtls',
            grant_type: 'implicit',
          })
          .type('form')
          .expect(tokenAuthSucceeded);
      });

      it('accepts the auth [2/2]', function () {
        return this.agent.post(route)
          .set('x-ssl-client-cert', eccrt.replace(RegExp('\\r?\\n', 'g'), ''))
          .send({
            client_id: 'client-self-signed-mtls',
            grant_type: 'implicit',
          })
          .type('form')
          .expect(tokenAuthSucceeded);
      });

      it('fails the auth when x-ssl-client-cert is not passed by the proxy', function () {
        return this.agent.post(route)
          .send({
            client_id: 'client-self-signed-mtls',
            grant_type: 'implicit',
          })
          .type('form')
          .expect(tokenAuthRejected);
      });

      it('fails the auth when x-ssl-client-cert does not match the registered ones', function () {
        return this.agent.post(route)
          .set('x-ssl-client-cert', eccrt.replace(RegExp('\\r?\\n', 'g'), ''))
          .send({
            client_id: 'client-self-signed-mtls-rsa',
            grant_type: 'implicit',
          })
          .type('form')
          .expect(tokenAuthRejected);
      });

      it('handles rotation of stale jwks', function () {
        nock('https://client.example.com/')
          .get('/jwks')
          .reply(200, JSON.stringify(mtlsKeys));

        return this.agent.post(route)
          .set('x-ssl-client-cert', rsacrt.replace(RegExp('\\r?\\n', 'g'), ''))
          .send({
            client_id: 'client-self-signed-mtls-jwks_uri',
            grant_type: 'implicit',
          })
          .type('form')
          .expect(tokenAuthSucceeded);
      });
    });
  }
});
