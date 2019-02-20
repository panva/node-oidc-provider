const { expect } = require('chai');

const bootstrap = require('../test_helper');

describe('default routing behavior', () => {
  describe('without mounting', () => {
    before(bootstrap(__dirname));

    it('handles unhandled verbs to known routes', function () {
      return this.agent.post('/.well-known/openid-configuration')
        .expect(404)
        .expect('content-type', /application\/json/)
        .expect({
          error: 'invalid_request',
          error_description: 'unrecognized route or not allowed method (POST on /.well-known/openid-configuration)',
        });
    });

    it('handles unknown routes', function () {
      return this.agent.get('/foobar')
        .expect(404)
        .expect('content-type', /application\/json/)
        .expect({
          error: 'invalid_request',
          error_description: 'unrecognized route or not allowed method (GET on /foobar)',
        });
    });

    it('handles unhandled verbs unhandled unknown routes', function () {
      return this.agent.trace('/foobar')
        .expect(404)
        .expect('content-type', /application\/json/)
        .expect({
          error: 'invalid_request',
          error_description: 'unrecognized route or not allowed method (TRACE on /foobar)',
        });
    });
  });

  describe('when mounted', () => {
    before(bootstrap(__dirname, { mountTo: '/oidc' }));

    it('handles being prefixed', function () {
      return this.agent.get('/oidc/.well-known/openid-configuration')
        .expect(200)
        .expect((res) => {
          Object.values(res.body).forEach((value) => {
            if (value.startsWith && value.startsWith('http')) {
              expect(value).to.match(new RegExp('^http://127.0.0.1:\\d{5}/oidc'));
            }
          });
        });
    });

    it('handles unrecognized route or not allowed methods with 404 json response', function () {
      return this.agent.get('/oidc/foobar')
        .expect(404)
        .expect('content-type', /application\/json/)
        .expect({
          error: 'invalid_request',
          error_description: 'unrecognized route or not allowed method (GET on /foobar)',
        });
    });

    it('does not interfere with the unmounted namespace', function () {
      return this.agent.get('/foobar')
        .expect(404)
        .expect('Not Found');
    });
  });
});
