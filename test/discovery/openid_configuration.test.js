'use strict';

const {
  request, provider, responses } = require('../test_helper')(__dirname);

const sinon = require('sinon');
const { InvalidRequestError } = require('../../lib/helpers/errors');
const { expect } = require('chai');

const route = '/.well-known/openid-configuration';

describe(route, function() {
  it('responds with json 200', function() {
    return request.get(route)
      .expect('Content-Type', /application\/json/)
      .expect(200);
  });

  describe('with errors', function() {
    before(function() {
      sinon.stub(provider, 'pathFor').throws(new InvalidRequestError());
    });

    after(function() {
      provider.pathFor.restore();
    });

    it('handles errors with json and corresponding status', function() {
      return request.get(route)
        .expect('Content-Type', /application\/json/)
        .expect(400);
    });

    it('emits discovery.error on errors', function() {
      let spy = sinon.spy();
      provider.once('discovery.error', spy);

      return request.get(route)
        .expect(function() {
          expect(spy.called).to.be.true;
        });
    });
  });

  describe('with exceptions', function() {
    before(function() {
      sinon.stub(provider, 'pathFor').throws();
    });

    after(function() {
      provider.pathFor.restore();
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
