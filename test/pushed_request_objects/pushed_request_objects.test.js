const { expect } = require('chai');
const sinon = require('sinon');

const JWT = require('../../lib/helpers/jwt');
const bootstrap = require('../test_helper');
const Provider = require('../../lib');

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
          expect(response.body).to.have.property('request_object_endpoint');
        });
    });
  });

  it('can only be enabled with request objects', () => {
    expect(() => {
      new Provider('http://localhost', { // eslint-disable-line no-new
        features: {
          pushedRequestObjects: { enabled: true },
          requestObjects: {
            request: false,
            requestUri: false,
          },
        },
      });
    }).to.throw('pushedRequestObjects is only available in conjuction with requestObjects.requestUri');
  });

  describe('Request Object Endpoint', () => {
    it('populates ctx.oidc.entities', function (done) {
      this.provider.use(this.assertOnce((ctx) => {
        expect(ctx.oidc.entities).to.have.keys('Client', 'RequestObject');
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
      this.provider.once('request_object.success', spy);

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
          expect(body).to.have.keys('aud', 'exp', 'iss', 'request_uri');
          expect(body).to.have.property('aud', 'client');
          expect(body).to.have.property('exp').and.is.a('number').above(Math.floor(Date.now() / 1000));
          expect(body).to.have.property('iss', this.provider.issuer);
          expect(body).to.have.property('request_uri').and.match(/^urn:ietf:params:oauth:request_uri:(.+)$/);
        });

      expect(spy).to.have.property('calledOnce', true);
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
      sinon.stub(this.TestAdapter.for('RequestObject'), 'upsert').callsFake(async () => { throw adapterThrow; });
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
          this.TestAdapter.for('RequestObject').upsert.restore();
        })
        .expect(500)
        .expect({
          error: 'server_error',
          error_description: 'oops! something went wrong',
        });
    });
  });

  describe('Using Pushed Request Objects', () => {
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

      expect(await this.provider.RequestObject.find(id)).to.be.ok;

      const auth = new this.AuthorizationRequest({
        client_id: 'client',
        state: undefined,
        redirect_uri: undefined,
        request_uri,
      });

      await this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(302)
        .expect(auth.validatePresence(['code']));

      expect(await this.provider.RequestObject.find(id)).not.to.be.ok;
    });

    it('handles expired or invalid pushed request object', async function () {
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

    it('handles expired or invalid pushed request object (when no client_id in the request)', async function () {
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
