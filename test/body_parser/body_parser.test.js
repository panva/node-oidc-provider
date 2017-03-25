const Provider = require('../../lib');
const Koa = require('koa');
const http = require('http');
const mount = require('koa-mount');
const supertest = require('supertest');
const upstreamParser = require('koa-body');

describe('body parser', function () {
  describe('application/x-www-form-urlencoded', function () {
    it('uses the upstream parser albeit reluctantly', async function () {
      const provider = new Provider('http://localhost:3000');
      await provider.initialize({
        clients: [{
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://rp.example.com/cb'],
          token_endpoint_auth_method: 'client_secret_post',
        }],
      });
      const app = new Koa();

      app.use(upstreamParser());
      app.use(mount('/op', provider.app));

      const server = http.createServer(app.callback()).listen();

      return supertest(server)
        .post('/op/token')
        .send({
          client_id: 'client',
          client_secret: 'secret',
          grant_type: 'authorization_code',
        })
        .type('form')
        .expect(400);
    });
  });

  describe('application/json', function () {
    it('uses the upstream parser albeit reluctantly', async function () {
      const provider = new Provider('http://localhost:3000', {
        features: { registration: true }
      });
      await provider.initialize();
      const app = new Koa();

      app.use(upstreamParser());
      app.use(mount('/op', provider.app));

      const server = http.createServer(app.callback()).listen();

      return supertest(server)
        .post('/op/reg')
        .send({
          redirect_uris: ['https://rp.example.com/cb'],
        })
        .type('json')
        .expect(201);
    });

    it('handles parsing errors', async function () {
      const provider = new Provider('http://localhost:3000', {
        features: { registration: true }
      });
      await provider.initialize();
      const server = http.createServer(provider.app.callback()).listen();

      return supertest(server)
        .post('/reg')
        .send('not a json')
        .type('json')
        .expect(400)
        .expect('{"error":"invalid_request","error_description":"couldnt parse the request body"}');
    });
  });
});
