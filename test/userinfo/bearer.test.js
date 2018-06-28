const { expect } = require('chai');

const bootstrap = require('../test_helper');

function failWith(code, error, error_description) {
  return ({ status, body, headers: { 'www-authenticate': wwwAuth } }) => {
    const { provider: { issuer } } = this;
    expect(status).to.eql(code);
    expect(body).to.have.property('error', error);
    expect(body).to.have.property('error_description', error_description);
    expect(wwwAuth).to.match(new RegExp(`^Bearer realm="${issuer}"`));
    expect(wwwAuth).to.match(new RegExp(`error="${error}"`));
  };
}

describe('providing Bearer token', () => {
  before(bootstrap(__dirname));
  context('invalid requests', () => {
    it('nothing provided', function () {
      return this.agent.get('/me')
        .expect(failWith.call(this, 400, 'invalid_request', 'no bearer token provided'));
    });

    it('provided twice', function () {
      return this.agent.get('/me')
        .auth('auth', 'provided')
        .query({ access_token: 'whaaat' })
        .expect(failWith.call(this, 400, 'invalid_request', 'bearer token must only be provided using one mechanism'));
    });

    it('bad Authorization header format (one part)', function () {
      return this.agent.get('/me')
        .set('Authorization', 'Bearer')
        .expect(failWith.call(this, 400, 'invalid_request', 'invalid authorization header value format'));
    });

    it('bad Authorization header format (more then two parts)', function () {
      return this.agent.get('/me')
        .auth('some three', { type: 'bearer' })
        .expect(failWith.call(this, 400, 'invalid_request', 'invalid authorization header value format'));
    });

    it('bad Authorization header format (not bearer)', function () {
      return this.agent.get('/me')
        .set('Authorization', 'Basic some')
        .expect(failWith.call(this, 400, 'invalid_request', 'invalid authorization header value format'));
    });

    it('[query] empty token provided', function () {
      return this.agent.get('/me')
        .query({ access_token: '' })
        .expect(failWith.call(this, 400, 'invalid_request', 'no bearer token provided'));
    });

    it('[body] empty token provided', function () {
      return this.agent.post('/me')
        .send('access_token=')
        .expect(failWith.call(this, 400, 'invalid_request', 'no bearer token provided'));
    });
  });
});
