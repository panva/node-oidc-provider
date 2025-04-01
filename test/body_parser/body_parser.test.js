import Koa from 'koa';
import mount from 'koa-mount';
import supertest from 'supertest';
import { koaBody as upstreamParser } from 'koa-body';
import sinon from 'sinon';
import { expect } from 'chai';

import Provider from '../../lib/index.js';

describe('body parser', () => {
  afterEach(() => {
    globalThis.server.removeAllListeners('request');
  });

  describe('application/x-www-form-urlencoded', () => {
    it('uses the upstream parser albeit reluctantly', async () => {
      const provider = new Provider('http://localhost:3000', {
        features: { clientCredentials: { enabled: true } },
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
      app.use(mount('/op', provider.koa()));

      globalThis.server.on('request', app.callback());

      return supertest(globalThis.server)
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
      app.use(mount('/op', provider.koa()));

      globalThis.server.on('request', app.callback());

      await supertest(globalThis.server)
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
        features: { registration: { enabled: true } },
      });
      const app = new Koa();

      app.use(upstreamParser());
      app.use(mount('/op', provider.koa()));

      globalThis.server.on('request', app.callback());

      return supertest(globalThis.server)
        .post('/op/reg')
        .send({
          redirect_uris: ['https://rp.example.com/cb'],
        })
        .type('json')
        .expect(201);
    });

    it('handles parsing errors', async () => {
      const provider = new Provider('http://localhost:3000', {
        features: { registration: { enabled: true } },
      });

      globalThis.server.on('request', provider.koa().callback());

      return supertest(globalThis.server)
        .post('/reg')
        .send('not a json')
        .type('json')
        .expect(400)
        .expect('{"error":"invalid_request","error_description":"failed to parse the request body"}');
    });
  });
});
