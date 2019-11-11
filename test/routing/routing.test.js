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
});
