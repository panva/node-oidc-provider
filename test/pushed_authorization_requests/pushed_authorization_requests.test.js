const { expect } = require('chai');
const sinon = require('sinon');
const jose = require('jose');

const JWT = require('../../lib/helpers/jwt');
const bootstrap = require('../test_helper');
const { Provider } = require('../../lib');

describe('Pushed Request Object', () => {
  before(bootstrap(__dirname));
  const route = '/request';

  before(async function () {
    const client = await this.provider.Client.find('client');
    this.key = client.keystore.get({ alg: 'HS256' });
  });

  describe('discovery', () => {
    it('extends the well known config', function () {
      return this.agent.get('/.well-known/openid-configuration')
        .expect((response) => {
          expect(response.body).not.to.have.property('request_object_endpoint');
          expect(response.body).to.have.property('pushed_authorization_request_endpoint');
        });
    });
  });

  it('can only be enabled with request objects', () => {
    expect(() => {
      new Provider('http://localhost', { // eslint-disable-line no-new
        features: {
          pushedAuthorizationRequests: { enabled: true },
          requestObjects: {
            request: false,
            requestUri: false,
          },
        },
      });
    }).to.throw('pushedAuthorizationRequests is only available in conjuction with requestObjects.requestUri');
  });

  describe('using a JAR request parameter', () => {
    describe('Pushed Authorization Request Endpoint', () => {
      it('populates ctx.oidc.entities', function (done) {
        this.provider.use(this.assertOnce((ctx) => {
          expect(ctx.oidc.entities).to.have.keys('Client', 'PushedAuthorizationRequest');
        }, done));

        JWT.sign({
          response_type: 'code',
          client_id: 'client',
        }, this.key, 'HS256').then((request) => {
          this.agent.post(route)
            .auth('client', 'secret')
            .type('form')
            .send({ request })
            .end(() => {});
        });
      });

      it('stores a request object and returns a uri', async function () {
        const spy = sinon.spy();
        this.provider.once('pushed_authorization_request.success', spy);

        await this.agent.post(route)
          .auth('client', 'secret')
          .type('form')
          .send({
            request: await JWT.sign({
              response_type: 'code',
              client_id: 'client',
            }, this.key, 'HS256'),
          })
          .expect(201)
          .expect(({ body }) => {
            expect(body).to.have.keys('expires_in', 'request_uri');
            expect(body).to.have.property('expires_in', 300);
            expect(body).to.have.property('request_uri').and.match(/^urn:ietf:params:oauth:request_uri:(.+)$/);
          });

        expect(spy).to.have.property('calledOnce', true);
      });

      it('ignores regular parameters when passing a JAR request', async function () {
        const spy = sinon.spy();
        this.provider.once('pushed_authorization_request.saved', spy);

        await this.agent.post(route)
          .auth('client', 'secret')
          .type('form')
          .send({
            nonce: 'foo',
            response_type: 'code token',
            request: await JWT.sign({
              response_type: 'code',
              client_id: 'client',
            }, this.key, 'HS256'),
          })
          .expect(201);

        expect(spy).to.have.property('calledOnce', true);
        const { request } = spy.args[0][0];
        const payload = jose.JWT.decode(request);
        expect(payload).not.to.have.property('nonce');
        expect(payload).to.have.property('response_type', 'code');
      });

      it('requires the registered request object signing alg be used', async function () {
        return this.agent.post(route)
          .auth('client', 'secret')
          .type('form')
          .send({
            request: await JWT.sign({
              response_type: 'code',
              client_id: 'client',
            }, undefined, 'none'),
          })
          .expect(400)
          .expect({
            error: 'invalid_request_object',
            error_description: 'the preregistered alg must be used in request or request_uri',
          });
      });

      it('requires the request object client_id to equal the authenticated client one', async function () {
        return this.agent.post(route)
          .auth('client', 'secret')
          .type('form')
          .send({
            request: await JWT.sign({
              response_type: 'code',
              client_id: 'client-foo',
            }, this.key, 'HS256'),
          })
          .expect(400)
          .expect({
            error: 'invalid_request_object',
            error_description: "request client_id must equal the authenticated client's client_id",
          });
      });

      it('remaps request validation errors to be related to the request object', async function () {
        return this.agent.post(route)
          .auth('client', 'secret')
          .type('form')
          .send({
            request: await JWT.sign({
              response_type: 'code',
              client_id: 'client',
              redirect_uri: 'https://rp.example.com/unlisted',
            }, this.key, 'HS256'),
          })
          .expect(400)
          .expect({
            error: 'invalid_request_object',
            error_description: "redirect_uri did not match any of the client's registered redirect_uris",
          });
      });

      it('leaves non OIDCProviderError alone', async function () {
        const adapterThrow = new Error('adapter throw!');
        sinon.stub(this.TestAdapter.for('PushedAuthorizationRequest'), 'upsert').callsFake(async () => { throw adapterThrow; });
        return this.agent.post(route)
          .auth('client', 'secret')
          .type('form')
          .send({
            request: await JWT.sign({
              response_type: 'code',
              client_id: 'client',
            }, this.key, 'HS256'),
          })
          .expect(() => {
            this.TestAdapter.for('PushedAuthorizationRequest').upsert.restore();
          })
          .expect(500)
          .expect({
            error: 'server_error',
            error_description: 'oops! something went wrong',
          });
      });
    });

    describe('Using Pushed Authorization Requests', () => {
      before(function () { return this.login(); });
      after(function () { return this.logout(); });

      it('allows the request_uri to be used', async function () {
        const { body: { request_uri } } = await this.agent.post(route)
          .auth('client', 'secret')
          .type('form')
          .send({
            request: await JWT.sign({
              scope: 'openid',
              response_type: 'code',
              client_id: 'client',
            }, this.key, 'HS256'),
          });

        let id = request_uri.split(':');
        id = id[id.length - 1];

        expect(await this.provider.PushedAuthorizationRequest.find(id)).to.be.ok;

        const auth = new this.AuthorizationRequest({
          client_id: 'client',
          state: undefined,
          redirect_uri: undefined,
          request_uri,
        });

        await this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(302)
          .expect(auth.validatePresence(['code']));

        expect(await this.provider.PushedAuthorizationRequest.find(id)).not.to.be.ok;
      });

      it('handles expired or invalid pushed authorization request object', async function () {
        const auth = new this.AuthorizationRequest({
          request_uri: 'urn:ietf:params:oauth:request_uri:foobar',
        });

        return this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(302)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request_uri'))
          .expect(auth.validateErrorDescription('request_uri is invalid or expired'));
      });

      it('handles expired or invalid pushed authorization request object (when no client_id in the request)', async function () {
        const renderSpy = sinon.spy(i(this.provider).configuration(), 'renderError');

        const auth = new this.AuthorizationRequest({
          client_id: undefined,
          request_uri: 'urn:ietf:params:oauth:request_uri:foobar',
        });

        return this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(() => {
            renderSpy.restore();
          })
          .expect(400)
          .expect(() => {
            expect(renderSpy.calledOnce).to.be.true;
            const renderArgs = renderSpy.args[0];
            expect(renderArgs[1]).to.have.property('error', 'invalid_request_uri');
            expect(renderArgs[1]).to.have.property('error_description', 'request_uri is invalid or expired');
          });
      });

      it('allows the request_uri to be used without passing client_id to the request', async function () {
        const { body: { request_uri } } = await this.agent.post(route)
          .auth('client', 'secret')
          .type('form')
          .send({
            request: await JWT.sign({
              scope: 'openid',
              response_type: 'code',
              client_id: 'client',
            }, this.key, 'HS256'),
          });

        const auth = new this.AuthorizationRequest({
          client_id: undefined,
          state: undefined,
          redirect_uri: undefined,
          request_uri,
        });

        return this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(302)
          .expect(auth.validatePresence(['code']));
      });
    });
  });

  describe('using a plain pushed authorization request', () => {
    describe('Pushed Authorization Request Endpoint', () => {
      it('populates ctx.oidc.entities', function (done) {
        this.provider.use(this.assertOnce((ctx) => {
          expect(ctx.oidc.entities).to.have.keys('Client', 'PushedAuthorizationRequest');
        }, done));

        this.agent.post(route)
          .auth('client', 'secret')
          .type('form')
          .send({
            response_type: 'code',
            client_id: 'client',
          })
          .end(() => {});
      });

      it('stores a request object and returns a uri', async function () {
        const spy = sinon.spy();
        this.provider.once('pushed_authorization_request.success', spy);

        await this.agent.post(route)
          .auth('client', 'secret')
          .type('form')
          .send({
            response_type: 'code',
            client_id: 'client',
          })
          .expect(201)
          .expect(({ body }) => {
            expect(body).to.have.keys('expires_in', 'request_uri');
            expect(body).to.have.property('expires_in', 300);
            expect(body).to.have.property('request_uri').and.match(/^urn:ietf:params:oauth:request_uri:(.+)$/);
          });

        expect(spy).to.have.property('calledOnce', true);
      });

      it('requires the registered request object signing alg be used', async function () {
        return this.agent.post(route)
          .type('form')
          .send({
            response_type: 'code',
            client_id: 'client-none',
          })
          .expect(400)
          .expect({
            error: 'invalid_request',
            error_description: 'Request Object must be used by this client',
          });
      });

      it('forbids request_uri to be used', async function () {
        return this.agent.post(route)
          .auth('client', 'secret')
          .type('form')
          .send({
            response_type: 'code',
            request_uri: 'https://rp.example.com/jar#foo',
          })
          .expect(400)
          .expect({
            error: 'invalid_request',
            error_description: '`request_uri` parameter must not be used at the pushed_authorization_request_endpoint',
          });
      });

      it('does not remap request validation errors to be related to the request object', async function () {
        return this.agent.post(route)
          .auth('client', 'secret')
          .type('form')
          .send({
            response_type: 'code',
            client_id: 'client',
            redirect_uri: 'https://rp.example.com/unlisted',
          })
          .expect(400)
          .expect({
            error: 'redirect_uri_mismatch',
            error_description: "redirect_uri did not match any of the client's registered redirect_uris",
          });
      });

      it('leaves non OIDCProviderError alone', async function () {
        const adapterThrow = new Error('adapter throw!');
        sinon.stub(this.TestAdapter.for('PushedAuthorizationRequest'), 'upsert').callsFake(async () => { throw adapterThrow; });
        return this.agent.post(route)
          .auth('client', 'secret')
          .type('form')
          .send({
            response_type: 'code',
            client_id: 'client',
          })
          .expect(() => {
            this.TestAdapter.for('PushedAuthorizationRequest').upsert.restore();
          })
          .expect(500)
          .expect({
            error: 'server_error',
            error_description: 'oops! something went wrong',
          });
      });
    });

    describe('Using Pushed Authorization Requests', () => {
      before(function () { return this.login(); });
      after(function () { return this.logout(); });

      it('allows the request_uri to be used', async function () {
        const { body: { request_uri } } = await this.agent.post(route)
          .auth('client', 'secret')
          .type('form')
          .send({
            scope: 'openid',
            response_type: 'code',
            client_id: 'client',
          });

        let id = request_uri.split(':');
        id = id[id.length - 1];

        expect(await this.provider.PushedAuthorizationRequest.find(id)).to.be.ok;

        const auth = new this.AuthorizationRequest({
          client_id: 'client',
          state: undefined,
          redirect_uri: undefined,
          request_uri,
        });

        await this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(302)
          .expect(auth.validatePresence(['code']));

        expect(await this.provider.PushedAuthorizationRequest.find(id)).not.to.be.ok;
      });

      it('allows the request_uri to be used without passing client_id to the request', async function () {
        const { body: { request_uri } } = await this.agent.post(route)
          .auth('client', 'secret')
          .type('form')
          .send({
            scope: 'openid',
            response_type: 'code',
            client_id: 'client',
          });

        const auth = new this.AuthorizationRequest({
          client_id: undefined,
          state: undefined,
          redirect_uri: undefined,
          request_uri,
        });

        return this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(302)
          .expect(auth.validatePresence(['code']));
      });
    });
  });
});
