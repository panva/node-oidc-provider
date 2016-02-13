'use strict';

const {
  request, provider, responses } = require('../test_helper')(__dirname);

const sinon = require('sinon');
const { expect } = require('chai');

const route = '/.well-known/openid-configuration';

describe(route, function() {
  describe('when ok', function() {

    it('responds with JSON 200', function() {
      return request.get(route)
        .expect('Content-Type', /application\/json/)
        .expect(200);
    });

  });

  describe('with errors', function() {
    before(function() {
      sinon.stub(provider, 'pathFor').throws();
    });

    after(function() {
      provider.pathFor.restore();
    });

    it('handles unexpected errors with JSON 500', function() {
      return request.get(route)
        .expect('Content-Type', /application\/json/)
        .expect(500, responses.serverErrorBody);
    });

    it('emits server_error on unexpected errors', function() {
      let spy = sinon.spy();
      provider.once('server_error', spy);

      return request.get(route)
        .expect(function() {
          expect(spy.called).to.be.true;
        });
    });
  });
});
