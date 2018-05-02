const bootstrap = require('../test_helper');
const { expect } = require('chai');
const sinon = require('sinon');
const base64url = require('base64url');

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

describe('registration features', () => {
  before(bootstrap(__dirname)); // agent, provider, TestAdapter

  context('POST /reg', () => {
    it('generates the id, secret that does not expire and reg access token and returns the defaulted values', function () {
      return this.agent.post('/reg')
        .send({
          redirect_uris: ['https://client.example.com/cb'],
        })
        .expect(201)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id', 'client_secret', 'registration_access_token');
          expect(response.body).to.have.property('client_secret_expires_at', 0);
          expect(response.body).to.have.property('application_type', 'web');
          expect(response.body).to.have.property('id_token_signed_response_alg', 'RS256');
          expect(response.body).to.have.property('token_endpoint_auth_method', 'client_secret_basic');
          expect(response.body).to.have.property('require_auth_time', false);
          expect(response.body).to.have.property('grant_types').and.eql(['authorization_code']);
          expect(response.body).to.have.property('response_types').and.eql(['code']);
          expect(response.body).to.have.property('registration_client_uri', `${this.provider.issuer}/reg/${response.body.client_id}`);
        });
    });

    it('populates ctx.oidc.entities', function (done) {
      this.provider.use(this.assertOnce((ctx) => {
        expect(ctx.oidc.entities).to.have.keys('Client', 'RegistrationAccessToken');
      }, done));

      this.agent.post('/reg')
        .send({
          redirect_uris: ['https://client.example.com/cb'],
        })
        .end(() => {});
    });

    it('omits the client_secret generation when it is not needed', function () {
      return this.agent.post('/reg')
        .send({
          token_endpoint_auth_method: 'none',
          redirect_uris: ['https://client.example.com/cb'],
          response_types: ['id_token'],
          grant_types: ['implicit'],
        })
        .expect(201)
        .expect((response) => {
          expect(response.body).not.to.have.property('client_secret');
          expect(response.body).not.to.have.property('client_secret_expires_at');
        });
    });

    it('issues the client_secret when needed for sig', function () {
      return this.agent.post('/reg')
        .send({
          token_endpoint_auth_method: 'none',
          redirect_uris: ['https://client.example.com/cb'],
          response_types: ['id_token'],
          grant_types: ['implicit'],
          id_token_signed_response_alg: 'HS256',
        })
        .expect(201)
        .expect((response) => {
          expect(response.body).to.have.property('client_secret');
          expect(response.body).to.have.property('client_secret_expires_at');
        });
    });

    it('issues the client_secret when needed for auth', function () {
      return this.agent.post('/reg')
        .send({
          token_endpoint_auth_method: 'client_secret_jwt',
          redirect_uris: ['https://client.example.com/cb'],
          response_types: ['id_token'],
          grant_types: ['implicit'],
        })
        .expect(201)
        .expect((response) => {
          expect(response.body).to.have.property('client_secret');
          expect(response.body).to.have.property('client_secret_expires_at');
        });
    });

    it('returns token-endpoint-like cache headers', function () {
      return this.agent.post('/reg')
        .send({
          redirect_uris: ['https://client.example.com/cb'],
        })
        .expect('pragma', 'no-cache')
        .expect('cache-control', 'no-cache, no-store');
    });

    it('stores the client and emits an event', function () {
      const spy = sinon.spy();
      this.provider.once('registration_create.success', spy);
      const adapter = this.TestAdapter.for('Client');
      const upsert = sinon.spy(adapter, 'upsert');

      return this.agent.post('/reg')
        .send({
          redirect_uris: ['https://client.example.com/cb'],
        })
        .expect(() => {
          expect(upsert.calledOnce).to.be.true;
          expect(spy.calledOnce).to.be.true;
          expect(spy.firstCall.args[0].constructor.name).to.equal('Client');
          expect(spy.firstCall.args[1]).to.have.property('oidc');
        });
    });

    it('uses the adapter to find stored clients', function () {
      const adapter = this.TestAdapter.for('Client');
      adapter.store.set('Client:foobar', {
        client_id: 'foobar',
        client_secret: 'foobarbaz',
        redirect_uris: ['https://client.example.com/cb'],
      });

      return this.provider.Client.find('foobar')
        .then((client) => {
          expect(client).to.be.ok;
        });
    });

    it('validates the parameters to be valid and responds with errors', function () {
      return this.agent.post('/reg')
        .send({
          grant_types: ['this is clearly wrong'],
          redirect_uris: ['https://client.example.com/cb'],
        })
        .expect(400)
        .expect(validateError('invalid_client_metadata'))
        .expect(validateErrorDescription(/^grant_types can only contain members/));
    });

    it('validates the parameters to be valid and responds with redirect_uri errors', function () {
      return this.agent.post('/reg')
        .send({
        // redirect_uris missing here
        })
        .expect(400)
        .expect(validateError('invalid_redirect_uri'))
        .expect(validateErrorDescription(/^redirect_uris is mandatory property/));
    });

    it('only accepts application/json POSTs', function () {
      return this.agent.post('/reg')
        .send({
          redirect_uris: ['https://client.example.com/cb'],
        })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_request',
          error_description: 'only application/json content-type POST bodies are supported',
        });
    });

    describe('initial access tokens', () => {
      describe('fix string one', () => {
        before(function () {
          const conf = i(this.provider).configuration();
          conf.features.registration = { initialAccessToken: 'foobar' };
        });
        after(function () {
          const conf = i(this.provider).configuration();
          conf.features.registration = true;
        });

        it('allows reg calls with the access tokens as a Bearer token [query]', function () {
          return this.agent.post('/reg')
            .send({
              redirect_uris: ['https://client.example.com/cb'],
            })
            .query({
              access_token: 'foobar',
            })
            .expect(201);
        });

        it('allows reg calls with the access tokens as a Bearer token [post]', function () {
          return this.agent.post('/reg')
            .send({
              redirect_uris: ['https://client.example.com/cb'],
              access_token: 'foobar',
            })
            .expect(201);
        });

        it('allows reg calls with the access tokens as a Bearer token [header]', function () {
          return this.agent.post('/reg')
            .auth('foobar', { type: 'bearer' })
            .send({
              redirect_uris: ['https://client.example.com/cb'],
            })
            .expect(201);
        });

        it('rejects calls with bad access token', function () {
          return this.agent.post('/reg')
            .send({
              redirect_uris: ['https://client.example.com/cb'],
            })
            .query({
              access_token: 'foobarbaz',
            })
            .expect(401);
        });
      });

      describe('using a model', () => {
        before(function () {
          const conf = i(this.provider).configuration();
          conf.features.registration = { initialAccessToken: true };

          const iat = new (this.provider.InitialAccessToken)({});
          return iat.save().then((value) => {
            this.token = value;
          });
        });
        after(function () {
          const conf = i(this.provider).configuration();
          conf.features.registration = true;
        });

        it('allows the developers to insert new tokens with no expiration', function () {
          return new (this.provider.InitialAccessToken)().save();
        });

        it('allows the developers to insert new tokens with expiration', function () {
          const IAT = this.provider.InitialAccessToken;
          return new IAT({
            expiresIn: 24 * 60 * 60,
          }).save().then((v) => {
            const jti = v.substring(0, 48);
            const token = this.TestAdapter.for('InitialAccessToken').syncFind(jti);
            expect(JSON.parse(base64url.decode(token.payload))).to.have.property('exp');
          });
        });

        it('allows reg calls with the access tokens as a Bearer token', function () {
          return this.agent.post('/reg')
            .send({
              redirect_uris: ['https://client.example.com/cb'],
            })
            .query({
              access_token: this.token,
            })
            .expect(201);
        });

        it('adds InitialAccessToken to ctx.oidc.entities', function (done) {
          this.provider.use(this.assertOnce((ctx) => {
            expect(ctx.oidc.entities).to.have.property('InitialAccessToken');
          }, done));

          this.agent.post('/reg')
            .send({
              redirect_uris: ['https://client.example.com/cb'],
            })
            .query({
              access_token: this.token,
            })
            .end(() => {});
        });

        it('rejects calls with bad access token', function () {
          return this.agent.post('/reg')
            .send({
              redirect_uris: ['https://client.example.com/cb'],
            })
            .query({
              access_token: 'foobarbaz',
            })
            .expect(401);
        });

        it('rejects calls with not found access token', function () {
          return this.agent.post('/reg')
            .send({
              redirect_uris: ['https://client.example.com/cb'],
            })
            .query({
              access_token: 'Loremipsumdolorsitametconsecteturadipisicingelitsed',
            })
            .expect(401);
        });

        it('rejects calls with manipulated access token', function () {
          return this.agent.post('/reg')
            .send({
              redirect_uris: ['https://client.example.com/cb'],
            })
            .query({
              access_token: this.token.slice(0, -1),
            })
            .expect(401);
        });
      });
    });
  });

  context('GET /reg/:clientId', () => {
    before(function () {
      return this.agent.post('/reg')
        .send({
          redirect_uris: ['https://client.example.com/cb'],
        })
        .expect((response) => {
          this.clientId = response.body.client_id;
          this.token = response.body.registration_access_token;
          this.registrationResponse = response.body;
        });
    });

    it('returns all available nonsecret metadata', function () {
      return this.agent.get(`/reg/${this.clientId}`)
        .query({
          access_token: this.token,
        })
        .expect(200)
        .expect('content-type', /application\/json/)
        .expect((response) => {
          expect(response.body).to.contain.keys('client_id', 'client_secret', 'registration_access_token');
          expect(response.body).to.have.property('client_secret_expires_at', 0);
          expect(response.body).to.have.property('application_type', 'web');
          expect(response.body).to.have.property('id_token_signed_response_alg', 'RS256');
          expect(response.body).to.have.property('token_endpoint_auth_method', 'client_secret_basic');
          expect(response.body).to.have.property('require_auth_time', false);
          expect(response.body).to.have.property('grant_types').and.eql(['authorization_code']);
          expect(response.body).to.have.property('response_types').and.eql(['code']);
          expect(response.body).to.have.property('registration_client_uri', `${this.provider.issuer}/reg/${response.body.client_id}`);
        });
    });

    it('populates ctx.oidc.entities', function (done) {
      this.provider.use(this.assertOnce((ctx) => {
        expect(ctx.oidc.entities).to.have.keys('Client', 'RegistrationAccessToken');
      }, done));

      this.agent.get(`/reg/${this.clientId}`)
        .query({
          access_token: this.token,
        })
        .end(() => {});
    });

    it('returns token-endpoint-like cache headers', function () {
      return this.agent.get(`/reg/${this.clientId}`)
        .query({
          access_token: this.token,
        })
        .expect('pragma', 'no-cache')
        .expect('cache-control', 'no-cache, no-store');
    });

    it('validates client is a valid client', function () {
      return this.agent.get('/reg/thisDOesnotCompute')
        .query({
          access_token: 'wahtever',
        })
        .expect(401)
        .expect(validateError('invalid_token'));
    });

    it('validates auth presence', function () {
      return this.agent.get(`/reg/${this.clientId}`)
        .expect(400)
        .expect(validateError('invalid_request'));
    });

    it('validates auth', function () {
      return this.agent.get(`/reg/${this.clientId}`)
        .query({
          access_token: 'invalid token',
        })
        .expect(401);
    });

    it('validates auth (notfoundtoken)', function () {
      return this.agent.get(`/reg/${this.clientId}`)
        .query({
          access_token: 'Loremipsumdolorsitametconsecteturadipisicingelitsed',
        })
        .expect(401);
    });

    it('accepts query', function () {
      return this.agent.get(`/reg/${this.clientId}`)
        .query({
          access_token: this.token,
        })
        .expect(200);
    });

    it('accepts header', function () {
      return this.agent.get(`/reg/${this.clientId}`)
        .auth(this.token, { type: 'bearer' })
        .expect(200);
    });

    it('invalidates registration_access_token if used on the wrong client', function () {
      const spy = sinon.spy();
      this.provider.once('token.revoked', spy);

      return this.agent.get('/reg/foobar')
        .query({
          access_token: this.token,
        })
        .expect('pragma', 'no-cache')
        .expect('cache-control', 'no-cache, no-store')
        .expect(401)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(spy.firstCall.args[0].constructor.name).to.equal('RegistrationAccessToken');
          expect(spy.firstCall.args[0].clientId).to.equal(this.clientId);
        });
    });
  });
});
