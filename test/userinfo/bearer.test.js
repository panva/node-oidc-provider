import { describe, before, it } from 'node:test';
import assert from 'node:assert/strict';
import bootstrap from '../test_helper.js';

describe('providing Bearer token', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  async function accessToken() {
    return new fixture.provider.AccessToken({
      client: await fixture.provider.Client.find('client'),
      accountId: fixture.loggedInAccountId,
      grantId: fixture.getGrantId(),
      scope: 'openid',
    }).save();
  }

  describe('invalid requests', () => {
    const fixture1 = Object.create(fixture);

    it('nothing provided', { timeout: 3000 }, () => fixture1.agent.get('/me')
        .expect(fixture1.failWith(401, 'invalid_token', 'no access token provided', undefined, 'Bearer'))
        .expect(fixture1.failWith(401, 'invalid_token', 'no access token provided', undefined, 'DPoP')));

    it('provided twice', { timeout: 3000 }, () => fixture1.agent.post('/me')
        .auth('header-token', { type: 'bearer' })
        .type('form')
        .send({ access_token: 'body-token' })
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

  describe('authorization header separator', () => {
    before(() => fixture.login(), { timeout: 3000 });

    it('accepts multiple ASCII spaces after the Bearer scheme', { timeout: 3000 }, async () => {
      const token = await accessToken();

      for (const spaces of ['  ', '     ']) {
        await fixture.agent.get('/me')
          .set('Authorization', `bEaReR${spaces}${token}`)
          .expect(200);
      }
    });
  });

  describe('query access tokens', () => {
    before(() => fixture.login(), { timeout: 3000 });

    it('ignores query-only access tokens by default', { timeout: 3000 }, async () => {
      const token = await accessToken();

      await fixture.agent.get('/me')
        .query({ access_token: token })
        .expect(fixture.failWith(401, 'invalid_token', 'no access token provided', undefined, 'Bearer'));
    });

    it('ignores repeated query access tokens with or without a valid header or body token', { timeout: 3000 }, async () => {
      const token = await accessToken();

      await fixture.agent.get('/me')
        .query('access_token=first&access_token=second')
        .expect(fixture.failWith(401, 'invalid_token', 'no access token provided', undefined, 'Bearer'));

      await fixture.agent.get('/me')
        .auth(token, { type: 'bearer' })
        .query('access_token=first&access_token=second')
        .expect(200);

      await fixture.agent.post('/me')
        .type('form')
        .send({ access_token: token })
        .query('access_token=first&access_token=second')
        .expect(200);
    });

    it('rejects repeated form body access tokens with or without a valid header token', { timeout: 3000 }, async () => {
      const token = await accessToken();

      for (const header of [false, true]) {
        const request = fixture.agent.post('/me')
          .type('form')
          .send('access_token=first&access_token=second');
        if (header) request.auth(token, { type: 'bearer' });

        await request.expect(fixture.failWith(400, 'invalid_request', "'access_token' parameter must not be provided twice"));
      }
    });

    it('accepts valid header and body tokens alongside ignored query tokens', { timeout: 3000 }, async () => {
      const token = await accessToken();

      await fixture.agent.get('/me')
        .auth(token, { type: 'bearer' })
        .query({ access_token: 'ignored-query-token' })
        .expect(200);

      await fixture.agent.post('/me')
        .type('form')
        .send({ access_token: token })
        .query({ access_token: 'ignored-query-token' })
        .expect(200);
    });

    it('exposes the POST body access token to extension helpers despite ignored query tokens', { timeout: 3000 }, async () => {
      const token = await accessToken();
      const configuration = i(fixture.provider).configuration;
      const original = configuration.findAccount;
      let calls = 0;
      configuration.findAccount = function (ctx, ...args) {
        assert.equal(ctx.oidc.params.access_token, token);
        calls += 1;
        return original.call(this, ctx, ...args);
      };

      try {
        await fixture.agent.post('/me')
          .type('form')
          .send({ access_token: token })
          .query({ access_token: 'ignored-query-token' })
          .expect(200);
        assert.equal(calls, 1);
      } finally {
        configuration.findAccount = original;
      }
    });

    it('still rejects repeated scope parameters when query access tokens are ignored', { timeout: 3000 }, async () => {
      const token = await accessToken();

      await fixture.agent.get('/me')
        .auth(token, { type: 'bearer' })
        .query('scope=openid&scope=openid&access_token=first&access_token=second')
        .expect(fixture.failWith(400, 'invalid_request', "'scope' parameter must not be provided twice"));
    });

    it('accepts query tokens and rejects duplicate mechanisms when explicitly enabled', { timeout: 3000 }, async () => {
      const token = await accessToken();
      const configuration = i(fixture.provider).configuration;
      const original = configuration.acceptQueryParamAccessTokens;
      configuration.acceptQueryParamAccessTokens = true;

      try {
        await fixture.agent.get('/me')
          .query({ access_token: token })
          .expect(200);

        await fixture.agent.get('/me')
          .query('access_token=first&access_token=second')
          .expect(fixture.failWith(400, 'invalid_request', "'access_token' parameter must not be provided twice"));

        await fixture.agent.post('/me')
          .type('form')
          .send({ access_token: token })
          .query('access_token=first&access_token=second')
          .expect(fixture.failWith(400, 'invalid_request', "'access_token' parameter must not be provided twice"));

        await fixture.agent.post('/me')
          .auth(token, { type: 'bearer' })
          .type('form')
          .send({})
          .query('access_token=first&access_token=second')
          .expect(fixture.failWith(400, 'invalid_request', "'access_token' parameter must not be provided twice"));

        await fixture.agent.get('/me')
          .auth(token, { type: 'bearer' })
          .query({ access_token: token })
          .expect(fixture.failWith(400, 'invalid_request', 'access token must only be provided using one mechanism'));

        await fixture.agent.post('/me')
          .type('form')
          .send({ access_token: token })
          .query({ access_token: token })
          .expect(fixture.failWith(400, 'invalid_request', 'access token must only be provided using one mechanism'));
      } finally {
        configuration.acceptQueryParamAccessTokens = original;
      }
    });
  });
});
