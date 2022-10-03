const Koa = require('koa');
const mount = require('koa-mount');
const supertest = require('supertest');
const upstreamParser = require('koa-body');
const sinon = require('sinon');
const { expect } = require('chai');

const { Provider } = require('../../lib');

describe('body parser', () => {
  afterEach(() => {
    global.server.removeAllListeners('request');
  });

  describe('application/x-www-form-urlencoded', () => {
    it('uses the upstream parser albeit reluctantly', async () => {
      const provider = new Provider('http://localhost:3000', {
        features: { clientCredentials: { enabled: true } },
        jwks: global.keystore.toJWKS(true),
        clients: [{
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: [],
          grant_types: ['client_credentials'],
          response_types: [],
          token_endpoint_auth_method: 'client_secret_post',
        }],
      });
      const app = new Koa();

      app.use(upstreamParser());
      app.use(mount('/op', provider.app));

      global.server.on('request', app.callback());

      return supertest(global.server)
        .post('/op/token')
        .send({
          client_id: 'client',
          client_secret: 'secret',
          grant_type: 'client_credentials',
        })
        .type('form')
        .expect(200);
    });

    it('removes all qs magic', async () => {
      const provider = new Provider('http://localhost:3000', {
        features: { clientCredentials: { enabled: true } },
        jwks: global.keystore.toJWKS(true),
        clients: [{
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: [],
          grant_types: ['client_credentials'],
          response_types: [],
          token_endpoint_auth_method: 'client_secret_post',
        }],
      });
      const spy = sinon.spy();
      provider.once('grant.success', spy);
      const app = new Koa();

      app.use(upstreamParser());
      app.use(mount('/op', provider.app));

      global.server.on('request', app.callback());

      await supertest(global.server)
        .post('/op/token')
        .send({
          client_id: 'client',
          client_secret: 'secret',
          grant_type: 'client_credentials',
          scope: [{ foo: 'bar' }],
        })
        .type('form')
        .expect(200);

      expect(
        spy.calledWithMatch({ oidc: { params: { scope: undefined } } }),
      ).to.be.true;
    });
  });

  describe('application/json', () => {
    it('uses the upstream parser albeit reluctantly', async () => {
      const provider = new Provider('http://localhost:3000', {
        jwks: global.keystore.toJWKS(true),
        features: { registration: { enabled: true } },
      });
      const app = new Koa();

      app.use(upstreamParser());
      app.use(mount('/op', provider.app));

      global.server.on('request', app.callback());

      return supertest(global.server)
        .post('/op/reg')
        .send({
          redirect_uris: ['https://rp.example.com/cb'],
        })
        .type('json')
        .expect(201);
    });

    it('handles parsing errors', async () => {
      const provider = new Provider('http://localhost:3000', {
        jwks: global.keystore.toJWKS(true),
        features: { registration: { enabled: true } },
      });

      global.server.on('request', provider.app.callback());

      return supertest(global.server)
        .post('/reg')
        .send('not a json')
        .type('json')
        .expect(400)
        .expect('{"error":"invalid_request","error_description":"failed to parse the request body"}');
    });
  });
});
