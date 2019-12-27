const { expect } = require('chai');
const sinon = require('sinon');

const bootstrap = require('../test_helper');

describe('registration features', () => {
  before(bootstrap(__dirname));

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
          expect(response.body).to.have.property('registration_client_uri', `${this.provider.issuer}${this.suitePath(`/reg/${response.body.client_id}`)}`);
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

    it('omits the client_secret generation when it is not needed and in doing so ignores provided client_secret and client_secret_expires_at', async function () {
      const { body: { client_id } } = await this.agent.post('/reg')
        .send({
          token_endpoint_auth_method: 'none',
          redirect_uris: ['https://client.example.com/cb'],
          response_types: ['id_token'],
          grant_types: ['implicit'],
          client_secret: 'foo',
          client_secret_expires_at: 123,
        })
        .expect(201)
        .expect((response) => {
          expect(response.body).not.to.have.property('client_secret');
          expect(response.body).not.to.have.property('client_secret_expires_at');
        });

      const client = await this.provider.Client.find(client_id);

      expect(client).not.to.have.property('clientSecret');
      expect(client).not.to.have.property('clientSecretExpiresAt');
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
          expect(spy.firstCall.args[0]).to.have.property('oidc');
          expect(spy.firstCall.args[1].constructor.name).to.equal('Client');
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
        .expect(this.failWith(400, 'invalid_client_metadata', "grant_types can only contain 'implicit', 'authorization_code', or 'refresh_token'"));
    });

    it('validates the parameters to be valid and responds with redirect_uri errors', function () {
      return this.agent.post('/reg')
        .send({
        // redirect_uris missing here
        })
        .expect(this.failWith(400, 'invalid_redirect_uri', 'redirect_uris is mandatory property'));
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
          error_description: 'only application/json content-type bodies are supported on POST /reg',
        });
    });

    describe('initial access tokens', () => {
      describe('fix string one', () => {
        before(function () {
          this.provider.enable('registration', { initialAccessToken: 'foobar' });
        });

        after(function () {
          this.provider.enable('registration', { initialAccessToken: undefined });
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
            .auth('foobarbaz', { type: 'bearer' })
            .expect(this.failWith(401, 'invalid_token', 'invalid token provided'));
        });
      });

      describe('using a model', () => {
        before(function () {
          this.provider.enable('registration', { initialAccessToken: true });

          const iat = new (this.provider.InitialAccessToken)({});
          return iat.save().then((value) => {
            this.token = value;
          });
        });

        after(function () {
          this.provider.enable('registration', { initialAccessToken: undefined });
        });

        it('allows the developers to insert new tokens with no expiration', function () {
          return new this.provider.InitialAccessToken().save().then((v) => {
            const jti = this.getTokenJti(v);
            const token = this.TestAdapter.for('InitialAccessToken').syncFind(jti);
            expect(token).not.to.have.property('exp');
          });
        });

        it('allows the developers to insert new tokens with expiration', function () {
          return new this.provider.InitialAccessToken({
            expiresIn: 24 * 60 * 60,
          }).save().then((v) => {
            const jti = this.getTokenJti(v);
            const token = this.TestAdapter.for('InitialAccessToken').syncFind(jti);
            expect(token).to.have.property('exp');
          });
        });

        it('allows reg calls with the access tokens as a Bearer token [query]', function () {
          return this.agent.post('/reg')
            .send({
              redirect_uris: ['https://client.example.com/cb'],
            })
            .query({
              access_token: this.token,
            })
            .expect(201);
        });

        it('allows reg calls with the access tokens as a Bearer token [post]', function () {
          return this.agent.post('/reg')
            .send({
              redirect_uris: ['https://client.example.com/cb'],
              access_token: this.token,
            })
            .expect(201);
        });

        it('allows reg calls with the access tokens as a Bearer token [header]', function () {
          return this.agent.post('/reg')
            .auth(this.token, { type: 'bearer' })
            .send({
              redirect_uris: ['https://client.example.com/cb'],
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
            .auth(this.token, { type: 'bearer' })
            .end(() => {});
        });

        it('rejects calls with bad access token', function () {
          return this.agent.post('/reg')
            .send({
              redirect_uris: ['https://client.example.com/cb'],
            })
            .auth('foobarbaz', { type: 'bearer' })
            .expect(this.failWith(401, 'invalid_token', 'invalid token provided'));
        });

        it('rejects calls with not found access token', function () {
          return this.agent.post('/reg')
            .send({
              redirect_uris: ['https://client.example.com/cb'],
            })
            .auth('Loremipsumdolorsitametconsecteturadipisicingelitsed', { type: 'bearer' })
            .expect(this.failWith(401, 'invalid_token', 'invalid token provided'));
        });

        it('rejects calls with manipulated access token', function () {
          return this.agent.post('/reg')
            .send({
              redirect_uris: ['https://client.example.com/cb'],
            })
            .auth(this.token.slice(0, -1), { type: 'bearer' })
            .expect(this.failWith(401, 'invalid_token', 'invalid token provided'));
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
        .auth(this.token, { type: 'bearer' })
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
          expect(response.body).to.have.property('registration_client_uri', `${this.provider.issuer}${this.suitePath(`/reg/${response.body.client_id}`)}`);
        });
    });

    it('populates ctx.oidc.entities', function (done) {
      this.provider.use(this.assertOnce((ctx) => {
        expect(ctx.oidc.entities).to.have.keys('Client', 'RegistrationAccessToken');
      }, done));

      this.agent.get(`/reg/${this.clientId}`)
        .auth(this.token, { type: 'bearer' })
        .end(() => {});
    });

    it('returns token-endpoint-like cache headers', function () {
      return this.agent.get(`/reg/${this.clientId}`)
        .auth(this.token, { type: 'bearer' })
        .expect('pragma', 'no-cache')
        .expect('cache-control', 'no-cache, no-store');
    });

    it('validates client is a valid client', function () {
      return this.agent.get('/reg/thisDOesnotCompute')
        .auth('wahtever', { type: 'bearer' })
        .expect(this.failWith(401, 'invalid_token', 'invalid token provided'));
    });

    it('validates auth presence', function () {
      return this.agent.get(`/reg/${this.clientId}`)
        .expect(this.failWith(400, 'invalid_request', 'no access token provided'));
    });

    it('validates auth', function () {
      return this.agent.get(`/reg/${this.clientId}`)
        .auth('invalidtoken', { type: 'bearer' })
        .expect(this.failWith(401, 'invalid_token', 'invalid token provided'));
    });

    it('validates auth (notfoundtoken)', function () {
      return this.agent.get(`/reg/${this.clientId}`)
        .auth('Loremipsumdolorsitametconsecteturadipisicingelitsed', { type: 'bearer' })
        .expect(this.failWith(401, 'invalid_token', 'invalid token provided'));
    });

    it('accepts query', function () {
      return this.agent.get(`/reg/${this.clientId}`)
        .auth(this.token, { type: 'bearer' })
        .expect(200);
    });

    it('accepts header', function () {
      return this.agent.get(`/reg/${this.clientId}`)
        .auth(this.token, { type: 'bearer' })
        .expect(200);
    });

    it('invalidates registration_access_token if used on the wrong client', function () {
      const spy = sinon.spy();
      this.provider.once('registration_access_token.destroyed', spy);

      return this.agent.get('/reg/foobar')
        .auth(this.token, { type: 'bearer' })
        .expect('pragma', 'no-cache')
        .expect('cache-control', 'no-cache, no-store')
        .expect(this.failWith(401, 'invalid_token', 'invalid token provided'))
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(spy.firstCall.args[0].constructor.name).to.equal('RegistrationAccessToken');
          expect(spy.firstCall.args[0].clientId).to.equal(this.clientId);
        });
    });

    it('cannot read non-dynamic clients', async function () {
      const rat = new (this.provider.RegistrationAccessToken)({ clientId: 'client' });
      const bearer = await rat.save();
      return this.agent.get('/reg/client')
        .auth(bearer, { type: 'bearer' })
        .expect(this.failWith(403, 'invalid_request', 'client does not have permission to read its record'));
    });
  });
});
