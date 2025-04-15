import bootstrap from '../test_helper.js';

describe('providing Bearer token', () => {
  before(bootstrap(import.meta.url));
  context('invalid requests', () => {
    it('nothing provided', function () {
      return this.agent.get('/me')
        .expect(this.failWith(401, 'invalid_token', 'no access token provided', undefined, 'Bearer'))
        .expect(this.failWith(401, 'invalid_token', 'no access token provided', undefined, 'DPoP'));
    });

    it('provided twice', function () {
      return this.agent.get('/me')
        .auth('auth', 'provided')
        .query({ access_token: 'whaaat' })
        .expect(this.failWith(400, 'invalid_request', 'access token must only be provided using one mechanism'));
    });

    it('bad Authorization header format (one part)', function () {
      return this.agent.get('/me')
        .set('Authorization', 'Bearer')
        .expect(this.failWith(400, 'invalid_request', 'invalid authorization header value format'));
    });

    it('bad Authorization header format (more then two parts)', function () {
      return this.agent.get('/me')
        .auth('some three', { type: 'bearer' })
        .expect(this.failWith(400, 'invalid_request', 'invalid authorization header value format'));
    });

    it('bad Authorization header format (not bearer)', function () {
      return this.agent.get('/me')
        .set('Authorization', 'Basic some')
        .expect(this.failWith(400, 'invalid_request', 'authorization header scheme must be `Bearer`'));
    });

    it('[query] empty token provided', function () {
      return this.agent.get('/me')
        .query({ access_token: '' })
        .expect(this.failWith(401, 'invalid_token', 'no access token provided', undefined, 'Bearer'))
        .expect(this.failWith(401, 'invalid_token', 'no access token provided', undefined, 'DPoP'));
    });

    it('[body] empty token provided', function () {
      return this.agent.post('/me')
        .send('access_token=')
        .expect(this.failWith(401, 'invalid_token', 'no access token provided', undefined, 'Bearer'))
        .expect(this.failWith(401, 'invalid_token', 'no access token provided', undefined, 'DPoP'));
    });

    it('empty body w/ auth header', function () {
      return this.agent.post('/me')
        .expect(this.failWith(401, 'invalid_token', 'no access token provided', undefined, 'Bearer'))
        .expect(this.failWith(401, 'invalid_token', 'no access token provided', undefined, 'DPoP'));
    });
  });
});
