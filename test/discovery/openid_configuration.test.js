const { expect } = require('chai');
const sinon = require('sinon').createSandbox();

const bootstrap = require('../test_helper');
const { InvalidRequest } = require('../../lib/helpers/errors');

const route = '/.well-known/openid-configuration';

describe(route, () => {
  before(bootstrap(__dirname));

  it('responds with json 200', function () {
    return this.agent.get(route)
      .expect('Content-Type', /application\/json/)
      .expect(200);
  });

  it('does not populate ctx.oidc.entities', function (done) {
    this.provider.use(this.assertOnce((ctx) => {
      expect(ctx.oidc.entities).to.be.empty;
    }, done));

    this.agent.get(route).end(() => {});
  });

  it('is configurable with extra properties', function () {
    i(this.provider).configuration('discovery').service_documentation = 'https://docs.example.com';
    i(this.provider).configuration('discovery').authorization_endpoint = 'this will not be used';

    return this.agent.get(route)
      .expect((response) => {
        expect(response.body).to.have.property('service_documentation', 'https://docs.example.com');
        expect(response.body.authorization_endpoint).not.to.equal('this will not be used');
      });
  });

  describe('with errors', () => {
    before(function () {
      sinon.stub(this.provider, 'pathFor').throws(new InvalidRequest());
    });

    after(sinon.restore);

    it('handles errors with json and corresponding status', function () {
      return this.agent.get(route)
        .expect('Content-Type', /application\/json/)
        .expect(400);
    });

    it('emits discovery.error on errors', function () {
      const spy = sinon.spy();
      this.provider.once('discovery.error', spy);

      return this.agent.get(route)
        .expect(() => {
          expect(spy.called).to.be.true;
        });
    });
  });

  describe('with exceptions', () => {
    before(function () {
      sinon.stub(this.provider, 'pathFor').throws();
    });

    after(sinon.restore);

    it('handles exceptions with json 500', function () {
      return this.agent.get(route)
        .expect('Content-Type', /application\/json/)
        .expect(500)
        .expect({
          error: 'server_error',
          error_description: 'oops! something went wrong',
        });
    });

    it('emits server_error on exceptions', function () {
      const spy = sinon.spy();
      this.provider.once('server_error', spy);

      return this.agent.get(route)
        .expect(() => {
          expect(spy.called).to.be.true;
        });
    });
  });
});
