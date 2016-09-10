'use strict';

const bootstrap = require('../test_helper');
const key = require('./ec.key');

const sinon = require('sinon');
const { InvalidRequestError } = require('../../lib/helpers/errors');
const { expect } = require('chai');

const route = '/certs';

describe(route, () => {
  const { provider, responses, agent } = bootstrap(__dirname);

  it('responds with json 200', () => {
    return agent.get(route)
      .expect('Content-Type', /application\/json/)
      .expect(200, { keys: [] });
  });

  describe('when populated with signing keys', () => {
    provider.setupCerts();

    it('responds with json 200', () => {
      return agent.get(route)
        .expect((res) => {
          expect(res.body.keys).to.have.length(1);
          expect(res.body.keys[0]).to.have.all.keys(['kty', 'kid', 'e', 'n']);
        });
    });
  });

  describe('EC keys', () => {
    provider.setupCerts([key]);

    it('responds with json 200', () => {
      return agent.get(route)
        .expect((res) => {
          expect(res.body.keys).to.have.length(1);
          expect(res.body.keys[0]).to.have.all.keys(['kty', 'kid', 'crv', 'x', 'y']);
        });
    });
  });

  describe('with errors', () => {
    before(() => {
      sinon.stub(provider.keystore, 'toJSON').throws(new InvalidRequestError());
    });

    after(() => {
      provider.keystore.toJSON.restore();
    });

    it('handles errors with json and corresponding status', () => {
      return agent.get(route)
        .expect('Content-Type', /application\/json/)
        .expect(400);
    });

    it('emits certificates.error on errors', () => {
      const spy = sinon.spy();
      provider.once('certificates.error', spy);

      return agent.get(route)
        .expect(() => {
          expect(spy.called).to.be.true;
        });
    });
  });

  describe('with exceptions', () => {
    before(() => {
      sinon.stub(provider.keystore, 'toJSON').throws();
    });

    after(() => {
      provider.keystore.toJSON.restore();
    });

    it('handles exceptions with json 500', () => {
      return agent.get(route)
        .expect('Content-Type', /application\/json/)
        .expect(500, responses.serverErrorBody);
    });

    it('emits server_error on exceptions', () => {
      const spy = sinon.spy();
      provider.once('server_error', spy);

      return agent.get(route)
        .expect(() => {
          expect(spy.called).to.be.true;
        });
    });
  });
});
