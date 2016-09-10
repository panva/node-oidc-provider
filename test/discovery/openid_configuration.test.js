'use strict';

const bootstrap = require('../test_helper');
const sinon = require('sinon');
const { InvalidRequestError } = require('../../lib/helpers/errors');
const { expect } = require('chai');

const route = '/.well-known/openid-configuration';

describe(route, () => {
  const { agent, provider, responses } = bootstrap(__dirname);

  it('responds with json 200', () => {
    return agent.get(route)
      .expect('Content-Type', /application\/json/)
      .expect(200);
  });

  it('is configurable with extra properties', () => {
    provider.configuration('discovery').service_documentation = 'https://docs.example.com';
    provider.configuration('discovery').authorization_endpoint = 'this will not be used';

    return agent.get(route)
      .expect((response) => {
        expect(response.body).to.have.property('service_documentation', 'https://docs.example.com');
        expect(response.body.authorization_endpoint).not.to.equal('this will not be used');
      });
  });

  describe('with errors', () => {
    before(() => {
      sinon.stub(provider, 'pathFor').throws(new InvalidRequestError());
    });

    after(() => {
      provider.pathFor.restore();
    });

    it('handles errors with json and corresponding status', () => {
      return agent.get(route)
        .expect('Content-Type', /application\/json/)
        .expect(400);
    });

    it('emits discovery.error on errors', () => {
      const spy = sinon.spy();
      provider.once('discovery.error', spy);

      return agent.get(route)
        .expect(() => {
          expect(spy.called).to.be.true;
        });
    });
  });

  describe('with exceptions', () => {
    before(() => {
      sinon.stub(provider, 'pathFor').throws();
    });

    after(() => {
      provider.pathFor.restore();
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
