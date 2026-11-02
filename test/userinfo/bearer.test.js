import { describe, before, it } from 'node:test';
import bootstrap from '../test_helper.js';

describe('providing Bearer token', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });
  describe('invalid requests', () => {
    const fixture1 = Object.create(fixture);

    it('nothing provided', { timeout: 3000 }, () => fixture1.agent.get('/me')
        .expect(fixture1.failWith(401, 'invalid_token', 'no access token provided', undefined, 'Bearer'))
        .expect(fixture1.failWith(401, 'invalid_token', 'no access token provided', undefined, 'DPoP')));

    it('provided twice', { timeout: 3000 }, () => fixture1.agent.get('/me')
        .auth('auth', 'provided')
        .query({ access_token: 'whaaat' })
        .expect(fixture1.failWith(400, 'invalid_request', 'access token must only be provided using one mechanism')));

    it('bad Authorization header format (one part)', { timeout: 3000 }, () => fixture1.agent.get('/me')
        .set('Authorization', 'Bearer')
        .expect(fixture1.failWith(400, 'invalid_request', 'invalid authorization header value format')));

    it('bad Authorization header format (more then two parts)', { timeout: 3000 }, () => fixture1.agent.get('/me')
        .auth('some three', { type: 'bearer' })
        .expect(fixture1.failWith(400, 'invalid_request', 'invalid authorization header value format')));

    it('bad Authorization header format (not bearer)', { timeout: 3000 }, () => fixture1.agent.get('/me')
        .set('Authorization', 'Basic some')
        .expect(fixture1.failWith(400, 'invalid_request', 'authorization header scheme must be `Bearer`')));

    it('[query] empty token provided', { timeout: 3000 }, () => fixture1.agent.get('/me')
        .query({ access_token: '' })
        .expect(fixture1.failWith(401, 'invalid_token', 'no access token provided', undefined, 'Bearer'))
        .expect(fixture1.failWith(401, 'invalid_token', 'no access token provided', undefined, 'DPoP')));

    it('[body] empty token provided', { timeout: 3000 }, () => fixture1.agent.post('/me')
        .send('access_token=')
        .expect(fixture1.failWith(401, 'invalid_token', 'no access token provided', undefined, 'Bearer'))
        .expect(fixture1.failWith(401, 'invalid_token', 'no access token provided', undefined, 'DPoP')));

    it('empty body w/ auth header', { timeout: 3000 }, () => fixture1.agent.post('/me')
        .expect(fixture1.failWith(401, 'invalid_token', 'no access token provided', undefined, 'Bearer'))
        .expect(fixture1.failWith(401, 'invalid_token', 'no access token provided', undefined, 'DPoP')));
  });
});
