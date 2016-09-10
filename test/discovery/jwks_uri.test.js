'use strict';

const bootstrap = require('../test_helper');
const key = require('./ec.key');

const sinon = require('sinon');
const { InvalidRequestError } = require('../../lib/helpers/errors');
const { expect } = require('chai');

const route = '/certs';

describe(route, function () {
  const { provider, responses, agent } = bootstrap(__dirname);

  it('responds with json 200', function () {
    return agent.get(route)
      .expect('Content-Type', /application\/json/)
      .expect(200, { keys: [] });
  });

  describe('when populated with signing keys', function () {
    provider.setupCerts();

    it('responds with json 200', function () {
      return agent.get(route)
        .expect(function (res) {
          expect(res.body.keys).to.have.length(1);
          expect(res.body.keys[0]).to.have.all.keys(['kty', 'kid', 'e', 'n']);
        });
    });
  });

  describe('EC keys', function () {
    provider.setupCerts([key]);

    it('responds with json 200', function () {
      return agent.get(route)
        .expect(function (res) {
          expect(res.body.keys).to.have.length(1);
          expect(res.body.keys[0]).to.have.all.keys(['kty', 'kid', 'crv', 'x', 'y']);
        });
    });
  });

  describe('with errors', function () {
    before(function () {
      sinon.stub(provider.keystore, 'toJSON').throws(new InvalidRequestError());
    });

    after(function () {
      provider.keystore.toJSON.restore();
    });

    it('handles errors with json and corresponding status', function () {
      return agent.get(route)
        .expect('Content-Type', /application\/json/)
        .expect(400);
    });

    it('emits certificates.error on errors', function () {
      const spy = sinon.spy();
      provider.once('certificates.error', spy);

      return agent.get(route)
        .expect(function () {
          expect(spy.called).to.be.true;
        });
    });
  });

  describe('with exceptions', function () {
    before(function () {
      sinon.stub(provider.keystore, 'toJSON').throws();
    });

    after(function () {
      provider.keystore.toJSON.restore();
    });

    it('handles exceptions with json 500', function () {
      return agent.get(route)
        .expect('Content-Type', /application\/json/)
        .expect(500, responses.serverErrorBody);
    });

    it('emits server_error on exceptions', function () {
      const spy = sinon.spy();
      provider.once('server_error', spy);

      return agent.get(route)
        .expect(function () {
          expect(spy.called).to.be.true;
        });
    });
  });
});
