import { describe, before, afterEach, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { parse as parseUrl } from 'node:url';
import { randomBytes } from 'node:crypto';

import { createSandbox } from 'sinon';
import base64url from 'base64url';

import bootstrap, { skipConsent, assertNoPendingInterceptors, mock } from '../test_helper.js';
import { InvalidClient } from '../../lib/helpers/errors.js';

const sinon = createSandbox();

async function consumeBody(body) {
  if (typeof body === 'string') return body;
  const chunks = [];
  for await (const chunk of body) chunks.push(chunk);
  return Buffer.concat(chunks).toString();
}

describe('Back-Channel Logout 1.0', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  afterEach(() => assertNoPendingInterceptors(), { timeout: 3000 });
  afterEach(() => sinon.restore(), { timeout: 3000 });

  describe('Client#backchannelLogout', () => {
    const fixture1 = Object.create(fixture);

    it('triggers the call', { timeout: 3000 }, async () => {
      const client = await fixture1.provider.Client.find('client');

      mock('https://client.example.com')
        .intercept({
          path: '/backchannel_logout',
          method: 'POST',
        })
        .reply(200, async (opts) => {
          const value = await consumeBody(opts.body);
          assert.match(value, /^logout_token=(([\w-]+\.?){3})$/);
          const header = JSON.parse(base64url.decode(RegExp.$1.split('.')[0]));
          ((actual) => { assert.ok('typ' in Object(actual)); assert.equal(actual.typ, 'logout+jwt'); })(header);
          const decoded = JSON.parse(base64url.decode(RegExp.$1.split('.')[1]));
          assert.deepEqual(new Set(Object.keys(decoded)), new Set(['sub', 'events', 'iat', 'exp', 'aud', 'iss', 'jti', 'sid']));
          ((actual) => { assert.ok('events' in Object(actual)); assert.deepEqual(actual.events, { 'http://schemas.openid.net/event/backchannel-logout': {} }); })(decoded);
          ((actual) => { assert.ok('aud' in Object(actual)); assert.equal(actual.aud, 'client'); })(decoded);
          ((actual) => { assert.ok('sub' in Object(actual)); assert.equal(actual.sub, 'subject'); })(decoded);
          ((actual) => { assert.ok('sid' in Object(actual)); assert.equal(actual.sid, 'foo'); })(decoded);
          return '';
        });

      return client.backchannelLogout('subject', 'foo');
    });

    it('omits sid when its not required', { timeout: 3000 }, async () => {
      const client = await fixture1.provider.Client.find('no-sid');

      mock('https://no-sid.example.com')
        .intercept({
          path: '/backchannel_logout',
          method: 'POST',
        })
        .reply(200, async (opts) => {
          const value = await consumeBody(opts.body);
          assert.match(value, /^logout_token=(([\w-]+\.?){3})$/);
          const decoded = JSON.parse(base64url.decode(RegExp.$1.split('.')[1]));
          assert.deepEqual(new Set(Object.keys(decoded)), new Set(['sub', 'events', 'iat', 'exp', 'aud', 'iss', 'jti']));
          ((actual) => { assert.ok('events' in Object(actual)); assert.deepEqual(actual.events, { 'http://schemas.openid.net/event/backchannel-logout': {} }); })(decoded);
          ((actual) => { assert.ok('aud' in Object(actual)); assert.equal(actual.aud, 'no-sid'); })(decoded);
          ((actual) => { assert.ok('sub' in Object(actual)); assert.equal(actual.sub, 'subject'); })(decoded);
          assert.ok(!('sid' in Object(decoded)));
          return '';
        });

      return client.backchannelLogout('subject', 'foo');
    });

    it('handles non-200 OK responses', { timeout: 3000 }, async () => {
      const client = await fixture1.provider.Client.find('no-sid');

      mock('https://no-sid.example.com')
        .intercept({
          path: '/backchannel_logout',
          method: 'POST',
        })
        .reply(500);

      return assert.rejects(client.backchannelLogout('subject', 'foo'), {
        message: 'expected 200 OK from https://no-sid.example.com/backchannel_logout, got: 500 Internal Server Error',
      });
    });
  });

  describe('discovery', () => {
    const fixture2 = Object.create(fixture);

    it('extends the well known config', { timeout: 3000 }, () => fixture2.agent.get('/.well-known/openid-configuration')
        .expect((response) => {
          assert.ok('end_session_endpoint' in Object(response.body));
          ((actual) => { assert.ok('backchannel_logout_supported' in Object(actual)); assert.equal(actual.backchannel_logout_supported, true); })(response.body);
          ((actual) => { assert.ok('backchannel_logout_session_supported' in Object(actual)); assert.equal(actual.backchannel_logout_session_supported, true); })(response.body);
        }));
  });

  describe('end_session extension', () => {
    const fixture3 = Object.create(fixture);

    beforeEach(() => fixture3.login({ scope: 'openid offline_access' }), { timeout: 3000 });
    afterEach(() => fixture3.logout(), { timeout: 3000 });

    skipConsent(fixture3);

    beforeEach(() => fixture3.agent.get('/auth')
        .query({
          client_id: 'client',
          scope: 'openid offline_access',
          prompt: 'consent',
          nonce: randomBytes(16).toString('base64url'),
          response_type: 'code id_token',
          redirect_uri: 'https://client.example.com/cb',
        })
        .expect(303)
        .expect((response) => {
          const { query } = parseUrl(response.headers.location.replace('#', '?'), true);
          assert.ok('code' in Object(query));
          assert.ok('id_token' in Object(query));
          fixture3.idToken = query.id_token;
          fixture3.code = query.code;
        }), { timeout: 3000 });

    it('makes sid available in id_token issued by authorization endpoint', { timeout: 3000 }, () => {
      const payload = JSON.parse(base64url.decode(fixture3.idToken.split('.')[1]));
      ((actual) => { assert.ok('sid' in Object(actual)); assert.equal(typeof actual.sid, 'string'); })(payload);
    });

    it('makes sid available in id_token issued by grant_type=authorization_code', { timeout: 3000 }, () => fixture3.agent.post('/token')
        .auth('client', 'secret')
        .type('form')
        .send({
          code: fixture3.code,
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.com/cb',
        })
        .expect(200)
        .expect((response) => {
          const payload = JSON.parse(base64url.decode(response.body.id_token.split('.')[1]));
          ((actual) => { assert.ok('sid' in Object(actual)); assert.equal(typeof actual.sid, 'string'); })(payload);
        }));

    it('makes sid available in id_token issued by grant_type=refresh_token', { timeout: 3000 }, (_t, done) => {
      fixture3.agent.post('/token')
        .auth('client', 'secret')
        .type('form')
        .send({
          code: fixture3.code,
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.com/cb',
        })
        .expect(200)
        .end((error, acResponse) => {
          if (error) { done(error); return; }
          fixture3.agent.post('/token')
            .auth('client', 'secret')
            .type('form')
            .send({
              refresh_token: acResponse.body.refresh_token,
              grant_type: 'refresh_token',
            })
            .expect(200)
            .expect((rtResponse) => {
              const payload = JSON.parse(base64url.decode(rtResponse.body.id_token.split('.')[1]));
              ((actual) => { assert.ok('sid' in Object(actual)); assert.equal(typeof actual.sid, 'string'); })(payload);
            })
            .end(done);
        });
    });

    it('triggers the backchannelLogout for all visited clients [when global logout]', { timeout: 3000 }, async () => {
      const session = fixture3.getSession();
      session.state = { secret: '123', clientId: 'client', postLogoutRedirectUri: 'https://rp.example.com/' };
      const params = { logout: 'yes', xsrf: '123' };
      const client = await fixture3.provider.Client.find('client');
      const client2 = await fixture3.provider.Client.find('second-client');
      const client3 = await fixture3.provider.Client.find('no-sid');

      sinon.spy(client, 'backchannelLogout');
      sinon.spy(client2, 'backchannelLogout');
      sinon.spy(client3, 'backchannelLogout');

      mock('https://client.example.com')
        .intercept({
          path: '/backchannel_logout',
          method: 'POST',
        })
        .reply(200);

      const successSpy = sinon.spy();
      fixture3.provider.once('backchannel.success', successSpy);
      const errorSpy = sinon.spy();
      fixture3.provider.once('backchannel.error', errorSpy);

      const { accountId } = session;

      return fixture3.agent.post('/session/end/confirm')
        .send(params)
        .type('form')
        .expect(303)
        .expect(() => {
          (() => {
            const { sid } = session.authorizations.client;
            assert.equal(client.backchannelLogout.called, true);
            assert.equal(client.backchannelLogout.calledWith(accountId, sid), true);
            client.backchannelLogout.restore();
            assert.equal(successSpy.calledOnce, true);
          })();
          (() => {
            const { sid } = session.authorizations['second-client'];
            assert.equal(client2.backchannelLogout.called, true);
            assert.equal(client2.backchannelLogout.calledWith(accountId, sid), true);
            client2.backchannelLogout.restore();
            assert.equal(errorSpy.calledOnce, true);
          })();
        });
    });

    it('skips stale clients during global backchannel logout', { timeout: 3000 }, async () => {
      const session = fixture3.getSession();
      const staleClientId = 'https://old.example.com/client';
      session.state = { secret: '123', clientId: 'client', postLogoutRedirectUri: 'https://rp.example.com/' };
      session.authorizations[staleClientId] = { sid: 'old-sid' };

      const client = await fixture3.provider.Client.find('client');
      sinon.spy(client, 'backchannelLogout');

      const find = sinon.stub(fixture3.provider.Client, 'find').callsFake(async function clientFind(clientId) {
        if (clientId === staleClientId) {
          throw new InvalidClient('client is invalid', 'client not found');
        }

        return find.wrappedMethod.call(this, clientId);
      });

      mock('https://client.example.com')
        .intercept({
          path: '/backchannel_logout',
          method: 'POST',
        })
        .reply(200);

      return fixture3.agent.post('/session/end/confirm')
        .send({ logout: 'yes', xsrf: '123' })
        .type('form')
        .expect(303)
        .expect(() => {
          assert.equal(find.calledWith(staleClientId), true);
          assert.equal(client.backchannelLogout.called, true);
          client.backchannelLogout.restore();
        });
    });

    it('still triggers the backchannelLogout for the specific client [when no global logout]', { timeout: 3000 }, async () => {
      const session = fixture3.getSession();
      session.state = { secret: '123', clientId: 'client', postLogoutRedirectUri: 'https://rp.example.com/' };
      const params = { xsrf: '123' };
      const client = await fixture3.provider.Client.find('client');
      const client2 = await fixture3.provider.Client.find('second-client');

      sinon.spy(client, 'backchannelLogout');
      sinon.spy(client2, 'backchannelLogout');

      const { accountId } = session;
      const { sid } = session.authorizations.client;

      return fixture3.agent.post('/session/end/confirm')
        .send(params)
        .type('form')
        .expect(303)
        .expect(() => {
          assert.equal(client.backchannelLogout.called, true);
          assert.equal(client.backchannelLogout.calledWith(accountId, sid), true);
          client.backchannelLogout.restore();
          assert.equal(client2.backchannelLogout.called, false);
          client2.backchannelLogout.restore();
        });
    });

    it('ignores the backchannelLogout when client does not support', { timeout: 3000 }, async () => {
      fixture3.getSession().state = { secret: '123', clientId: 'client', postLogoutRedirectUri: 'https://rp.example.com/' };
      const params = { logout: 'yes', xsrf: '123' };
      const client = await fixture3.provider.Client.find('client');
      const client2 = await fixture3.provider.Client.find('second-client');
      delete client.backchannelLogoutUri;

      sinon.spy(client, 'backchannelLogout');
      sinon.spy(client2, 'backchannelLogout');

      return fixture3.agent.post('/session/end/confirm')
        .send(params)
        .type('form')
        .expect(303)
        .expect(() => {
          assert.equal(client.backchannelLogout.called, false);
          client.backchannelLogout.restore();
          assert.equal(client2.backchannelLogout.called, true);
        });
    });
  });
});
