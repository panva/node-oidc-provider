'use strict';

const {
  request, provider, responses, setupCerts
} = require('../test_helper')(__dirname);

const sinon = require('sinon');
const { InvalidRequestError } = require('../../lib/helpers/errors');
const { expect } = require('chai');

const route = '/certs';

describe(route, function() {
  it('responds with json 200', function() {
    return request.get(route)
      .expect('Content-Type', /application\/json/)
      .expect(200, { keys: [] });
  });

  describe('when populated with signing keys', function() {
    setupCerts();

    it('responds with json 200', function() {
      return request.get(route)
        .expect(function(res) {
          expect(res.body.keys).to.have.length(1);
          expect(res.body.keys[0]).to.have.all.keys(['kty', 'kid', 'use', 'e', 'n']);
        });
    });

  });

  describe('EC keys', function() {
    setupCerts([require('./ec.key')]);

    it('responds with json 200', function() {
      return request.get(route)
        .expect(function(res) {
          expect(res.body.keys).to.have.length(1);
          expect(res.body.keys[0]).to.have.all.keys(['kty', 'kid', 'use', 'crv', 'x', 'y']);
        });
    });

  });

  describe('with errors', function() {
    before(function() {
      sinon.stub(provider.keystore, 'toJSON').throws(new InvalidRequestError());
    });

    after(function() {
      provider.keystore.toJSON.restore();
    });

    it('handles errors with json and corresponding status', function() {
      return request.get(route)
        .expect('Content-Type', /application\/json/)
        .expect(400);
    });

    it('emits certificates.error on errors', function() {
      let spy = sinon.spy();
      provider.once('certificates.error', spy);

      return request.get(route)
        .expect(function() {
          expect(spy.called).to.be.true;
        });
    });
  });

  describe('with exceptions', function() {
    before(function() {
      sinon.stub(provider.keystore, 'toJSON').throws();
    });

    after(function() {
      provider.keystore.toJSON.restore();
    });

    it('handles exceptions with json 500', function() {
      return request.get(route)
        .expect('Content-Type', /application\/json/)
        .expect(500, responses.serverErrorBody);
    });

    it('emits server_error on exceptions', function() {
      let spy = sinon.spy();
      provider.once('server_error', spy);

      return request.get(route)
        .expect(function() {
          expect(spy.called).to.be.true;
        });
    });
  });
});
