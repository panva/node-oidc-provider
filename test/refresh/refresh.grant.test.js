import { describe, before, afterEach, beforeEach, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { parse as parseUrl } from 'node:url';

import { createSandbox } from 'sinon';
import base64url from 'base64url';
import timekeeper from 'timekeeper';

import bootstrap, { skipConsent } from '../test_helper.js';
import { Account } from '../models.js';

const sinon = createSandbox();

const route = '/token';

function errorDetail(spy) {
  return spy.args[0][1].error_detail;
}

describe('grant_type=refresh_token', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  afterEach(() => timekeeper.reset(), { timeout: 3000 });
  afterEach(() => {
    fixture.provider.removeAllListeners();
  }, { timeout: 3000 });
  afterEach(() => sinon.restore(), { timeout: 3000 });

  beforeEach(() => fixture.login({ scope: 'openid email offline_access' }), { timeout: 3000 });
  afterEach(() => fixture.logout(), { timeout: 3000 });
  skipConsent(fixture);

  beforeEach((_t, done) => {
    fixture.agent.get('/auth')
      .query({
        client_id: 'client',
        scope: 'openid email offline_access',
        prompt: 'consent',
        response_type: 'code',
        redirect_uri: 'https://client.example.com/cb',
        nonce: 'foobarnonce',
      })
      .expect(303)
      .end((err, authResponse) => {
        if (err) {
          return done(err);
        }

        const { query: { code } } = parseUrl(authResponse.headers.location, true);

        return fixture.agent.post(route)
          .auth('client', 'secret')
          .type('form')
          .send({
            code,
            grant_type: 'authorization_code',
            redirect_uri: 'https://client.example.com/cb',
          })
          .expect(200)
          .expect((response) => {
            assert.ok('refresh_token' in Object(response.body));
            const jti = fixture.getTokenJti(response.body.refresh_token);
            fixture.refreshToken = fixture.TestAdapter.for('RefreshToken').syncFind(jti);
            ((actual) => { assert.ok('gty' in Object(actual)); assert.equal(actual.gty, 'authorization_code'); })(fixture.refreshToken);
            fixture.rt = response.body.refresh_token;
          })
          .end(done);
      });
  }, { timeout: 3000 });

  afterEach(() => {
    fixture.provider.removeAllListeners();
  }, { timeout: 3000 });

  it('returns the right stuff', { timeout: 3000 }, () => {
    const { rt } = fixture;
    const spy = sinon.spy();
    fixture.provider.on('grant.success', spy);

    return fixture.agent.post(route)
      .auth('client', 'secret')
      .send({
        refresh_token: rt,
        grant_type: 'refresh_token',
      })
      .type('form')
      .expect(200)
      .expect(() => {
        assert.equal(spy.calledOnce, true);
      })
      .expect(({ body }) => {
        assert.deepEqual(new Set(Object.keys(body)), new Set(['access_token', 'id_token', 'expires_in', 'token_type', 'refresh_token', 'scope']));
        const refreshIdToken = JSON.parse(base64url.decode(body.id_token.split('.')[1]));
        ((actual) => { assert.ok('nonce' in Object(actual)); assert.equal(actual.nonce, 'foobarnonce'); })(refreshIdToken);
        ((actual) => { assert.ok('refresh_token' in Object(actual)); assert.equal(typeof actual.refresh_token, 'string'); })(body);
      });
  });

  it('populates ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
    fixture.assertOnce((ctx) => {
      assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Account', 'Grant', 'Client', 'AccessToken', 'RefreshToken']));
      ((actual) => { assert.ok('gty' in Object(actual)); assert.equal(actual.gty, 'authorization_code'); })(ctx.oidc.entities.RefreshToken);
      ((actual) => { assert.ok('gty' in Object(actual)); assert.equal(actual.gty, 'authorization_code refresh_token'); })(ctx.oidc.entities.AccessToken);
    }, done);

    fixture.agent.post(route)
      .auth('client', 'secret')
      .send({
        refresh_token: fixture.rt,
        grant_type: 'refresh_token',
      })
      .type('form')
      .end(() => {});
  });

  describe('validates', () => {
    const fixture1 = Object.create(fixture);

    describe('', () => {
      const fixture2 = Object.create(fixture1);

      before(() => {
        const { ttl } = i(fixture2.provider).configuration;
        fixture2.prev = ttl.RefreshToken;
        ttl.RefreshToken = 5;
      }, { timeout: 3000 });

      after(() => {
        i(fixture2.provider).configuration.ttl.RefreshToken = fixture2.prev;
      }, { timeout: 3000 });

      it('validates the refresh token is not expired', { timeout: 3000 }, () => {
        timekeeper.travel(Date.now() + (10 * 1000));
        const { rt } = fixture2;
        const spy = sinon.spy();
        fixture2.provider.on('grant.error', spy);

        return fixture2.agent.post(route)
          .auth('client', 'secret')
          .send({
            refresh_token: rt,
            grant_type: 'refresh_token',
          })
          .type('form')
          .expect(400)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
            assert.equal(errorDetail(spy), 'refresh token is expired');
          })
          .expect((response) => {
            ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
          });
      });
    });

    it('validates that token belongs to client', { timeout: 3000 }, () => {
      const { rt } = fixture1;
      const spy = sinon.spy();
      fixture1.provider.on('grant.error', spy);

      return fixture1.agent.post(route)
        .auth('client2', 'secret')
        .send({
          refresh_token: rt,
          grant_type: 'refresh_token',
        })
        .type('form')
        .expect(400)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'client mismatch');
        })
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
        });
    });

    it('scopes are not getting extended (single)', { timeout: 3000 }, () => {
      const { rt } = fixture1;
      const spy = sinon.spy();
      fixture1.provider.on('grant.error', spy);

      return fixture1.agent.post(route)
        .auth('client', 'secret')
        .send({
          refresh_token: rt,
          grant_type: 'refresh_token',
          scope: 'openid profile',
        })
        .type('form')
        .expect(400)
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_scope'); })(response.body);
          ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'refresh token missing requested scope'); })(response.body);
          ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, 'profile'); })(response.body);
        });
    });

    it('scopes are not getting extended (multiple)', { timeout: 3000 }, () => {
      const { rt } = fixture1;
      const spy = sinon.spy();
      fixture1.provider.on('grant.error', spy);

      return fixture1.agent.post(route)
        .auth('client', 'secret')
        .send({
          refresh_token: rt,
          grant_type: 'refresh_token',
          scope: 'openid profile address',
        })
        .type('form')
        .expect(400)
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_scope'); })(response.body);
          ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'refresh token missing requested scopes'); })(response.body);
          ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, 'profile address'); })(response.body);
        });
    });

    it('scopes can get slimmer (1/2) - no openid scope, ID Token is not issued', { timeout: 3000 }, () => {
      const { rt } = fixture1;
      const spy = sinon.spy();
      fixture1.provider.on('access_token.saved', spy);
      fixture1.provider.on('access_token.issued', spy);

      return fixture1.agent.post(route)
        .auth('client', 'secret')
        .send({
          refresh_token: rt,
          grant_type: 'refresh_token',
          scope: 'email',
        })
        .type('form')
        .expect(200)
        .expect(({ body }) => {
          ((actual) => { assert.ok('kind' in Object(actual)); assert.equal(actual.kind, 'AccessToken'); })(spy.firstCall.args[0]);
          ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, 'email'); })(spy.firstCall.args[0]);
          ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, 'email'); })(body);
          assert.ok(!('id_token' in Object(body)));
        });
    });

    it('scopes can get slimmer (2/2) - openid scope is present, ID Token is issued', { timeout: 3000 }, () => {
      const { rt } = fixture1;
      const spy = sinon.spy();
      fixture1.provider.on('access_token.saved', spy);
      fixture1.provider.on('access_token.issued', spy);

      return fixture1.agent.post(route)
        .auth('client', 'secret')
        .send({
          refresh_token: rt,
          grant_type: 'refresh_token',
          scope: 'openid email',
        })
        .type('form')
        .expect(200)
        .expect(({ body }) => {
          ((actual) => { assert.ok('kind' in Object(actual)); assert.equal(actual.kind, 'AccessToken'); })(spy.firstCall.args[0]);
          ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, 'openid email'); })(spy.firstCall.args[0]);
          ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, 'openid email'); })(body);
          assert.ok('id_token' in Object(body));
        });
    });

    it('passes the slimmed down scope to the account claims helper', { timeout: 3000 }, () => {
      const { rt } = fixture1;
      const claims = sinon.spy(Account.prototype, 'claims');

      return fixture1.agent.post(route)
        .auth('client', 'secret')
        .send({
          refresh_token: rt,
          grant_type: 'refresh_token',
          scope: 'openid',
        })
        .type('form')
        .expect(200)
        .expect(({ body }) => {
          ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, 'openid'); })(body);
          const idToken = claims.getCalls().find(({ args: [use] }) => use === 'id_token');
          assert(idToken, 'account claims were not resolved for the ID Token');
          // and not the refresh token's original 'openid email offline_access'
          assert.equal(idToken.args[1], 'openid');
        });
    });

    it('validates account is still there', { timeout: 3000 }, () => {
      const { rt } = fixture1;
      sinon.stub(i(fixture1.provider).configuration, 'findAccount').callsFake(() => Promise.resolve());

      const spy = sinon.spy();
      fixture1.provider.on('grant.error', spy);

      return fixture1.agent.post(route)
        .auth('client', 'secret')
        .send({
          refresh_token: rt,
          grant_type: 'refresh_token',
        })
        .type('form')
        .expect(400)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'refresh token invalid (referenced account not found)');
        })
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
        });
    });
  });

  it('refresh_token presence', { timeout: 3000 }, () => fixture.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'refresh_token',
      })
      .type('form')
      .expect(400)
      .expect((response) => {
        ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request'); })(response.body);
        ((actual) => { assert.ok('error_description' in Object(actual)); assert.match(actual.error_description, /missing required parameter/); })(response.body);
        ((actual) => { assert.ok('error_description' in Object(actual)); assert.match(actual.error_description, /refresh_token/); })(response.body);
      }));

  it('code being "found"', { timeout: 3000 }, () => {
    const spy = sinon.spy();
    fixture.provider.on('grant.error', spy);
    return fixture.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'refresh_token',
        refresh_token: 'eyJraW5kIjoiUmVmcmVzaFRva2VuIiwianRpIjoiYzc4ZjdlYjMtZjdkYi00ZDNmLWFjNzUtYTY3MTA2NTUxOTYyIiwiaWF0IjoxNDYzNjY5Mjk1LCJleHAiOjE0NjM2NzEwOTUsImlzcyI6Imh0dHA6Ly8xMjcuMC4wLjE6NjAxNDMifQ.KJxy5D3_lwAlBs6E0INhrjJm1Bk9BrPlRacoyYztt5s_yxWidNua_eSvMbmRqqIq6t2hGguW7ZkEJhVHGNxvaHctGjSIrAOjaZhh1noqP9keXnATf2N2Twdsz-Viim5F0A7vu9OlhNm75P-yfreOTmmbQ4goM5449Dvq_xli2gmgg1j4HnASAI3YuxAzCCSJPbJDE2UL0-_q7nIvH0Ak2RuNbTJLjYt36jymfLnJ2OOe1z9N2RuZrIQQy7ksAIJkJs_3SJ0RYKDBtUplPC2fK7qsNk4wUTgxLJE3Xp_sJZKwVG2ascsVdexVnUCxqDN3xt9MpI14M3Zw7UwGghdIfQ',
      })
      .type('form')
      .expect(400)
      .expect(() => {
        assert.equal(spy.calledOnce, true);
        assert.equal(errorDetail(spy), 'refresh token not found');
      })
      .expect((response) => {
        ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
      });
  });

  describe('rotateRefreshToken=true', () => {
    const fixture3 = Object.create(fixture);

    before(() => {
      i(fixture3.provider).configuration.rotateRefreshToken = true;
    }, { timeout: 3000 });

    after(() => {
      i(fixture3.provider).configuration.rotateRefreshToken = false;
    }, { timeout: 3000 });

    it('populates ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
      fixture3.assertOnce((ctx) => {
        assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Account', 'Grant', 'Client', 'AccessToken', 'RotatedRefreshToken', 'RefreshToken']));
        assert.notDeepEqual(ctx.oidc.entities.RotatedRefreshToken, ctx.oidc.entities.RefreshToken);
        ((actual) => { assert.ok('gty' in Object(actual)); assert.equal(actual.gty, 'authorization_code'); })(ctx.oidc.entities.RotatedRefreshToken);
        ((actual) => { assert.ok('gty' in Object(actual)); assert.equal(actual.gty, 'authorization_code refresh_token'); })(ctx.oidc.entities.RefreshToken);
        ((actual) => { assert.ok('gty' in Object(actual)); assert.equal(actual.gty, 'authorization_code refresh_token'); })(ctx.oidc.entities.AccessToken);
      }, done);

      fixture3.agent.post(route)
        .auth('client', 'secret')
        .send({
          refresh_token: fixture3.rt,
          grant_type: 'refresh_token',
        })
        .type('form')
        .end(() => {});
    });

    it('issues a new refresh token and consumes the old one', { timeout: 3000 }, () => {
      const { rt } = fixture3;
      const consumeSpy = sinon.spy();
      const issueSpy = sinon.spy();
      fixture3.provider.on('refresh_token.consumed', consumeSpy);
      fixture3.provider.on('refresh_token.saved', issueSpy);

      return fixture3.agent.post(route)
        .auth('client', 'secret')
        .send({
          refresh_token: rt,
          grant_type: 'refresh_token',
        })
        .type('form')
        .expect(200)
        .expect(() => {
          assert.equal(consumeSpy.calledOnce, true);
          assert.equal(issueSpy.called, true);
        })
        .expect((response) => {
          assert.deepEqual(new Set(Object.keys(response.body)), new Set(['access_token', 'id_token', 'expires_in', 'token_type', 'refresh_token', 'scope']));
          const refreshIdToken = JSON.parse(base64url.decode(response.body.id_token.split('.')[1]));
          ((actual) => { assert.ok('nonce' in Object(actual)); assert.equal(actual.nonce, 'foobarnonce'); })(refreshIdToken);
          ((actual) => { assert.ok('refresh_token' in Object(actual)); assert.notEqual(actual.refresh_token, rt); })(response.body);
        });
    });

    it('the new refresh token has identical scope to the old one', { timeout: 3000 }, () => {
      const { rt } = fixture3;
      const consumeSpy = sinon.spy();
      const issueSpy = sinon.spy();
      fixture3.provider.on('refresh_token.consumed', consumeSpy);
      fixture3.provider.on('refresh_token.saved', issueSpy);
      fixture3.provider.on('access_token.saved', issueSpy);
      fixture3.provider.on('access_token.issued', issueSpy);

      return fixture3.agent.post(route)
        .auth('client', 'secret')
        .send({
          refresh_token: rt,
          grant_type: 'refresh_token',
        })
        .type('form')
        .expect(200)
        .expect(() => {
          assert.equal(consumeSpy.calledOnce, true);
          assert.equal(issueSpy.calledTwice, true);
          ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, 'openid email offline_access'); })(consumeSpy.firstCall.args[0]);
          ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, 'openid email offline_access'); })(issueSpy.firstCall.args[0]);
        });
    });

    it('the new refresh token has identical scope to the old one even if the access token is requested with less scopes', { timeout: 3000 }, () => {
      const { rt } = fixture3;
      const consumeSpy = sinon.spy();
      const issueSpy = sinon.spy();
      fixture3.provider.on('refresh_token.consumed', consumeSpy);
      fixture3.provider.on('refresh_token.saved', issueSpy);
      fixture3.provider.on('access_token.saved', issueSpy);
      fixture3.provider.on('access_token.issued', issueSpy);

      return fixture3.agent.post(route)
        .auth('client', 'secret')
        .send({
          refresh_token: rt,
          scope: 'openid',
          grant_type: 'refresh_token',
        })
        .type('form')
        .expect(200)
        .expect(() => {
          assert.equal(consumeSpy.calledOnce, true);
          assert.equal(issueSpy.calledTwice, true);
          ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, 'openid email offline_access'); })(consumeSpy.firstCall.args[0]);
          ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, 'openid email offline_access'); })(issueSpy.firstCall.args[0]);
          ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, 'openid'); })(issueSpy.secondCall.args[0]);
        });
    });

    it('revokes the complete grant if the old token is used again', { timeout: 3000 }, () => {
      const { rt } = fixture3;

      const grantRevokeSpy = sinon.spy();
      const tokenDestroySpy = sinon.spy();
      fixture3.provider.on('grant.revoked', grantRevokeSpy);
      fixture3.provider.on('refresh_token.destroyed', tokenDestroySpy);

      return assert.rejects(Promise.all([
        fixture3.agent.post(route)
          .auth('client', 'secret')
          .send({
            refresh_token: rt,
            grant_type: 'refresh_token',
          })
          .type('form')
          .expect(200), // one of them will fail.
        fixture3.agent.post(route)
          .auth('client', 'secret')
          .send({
            refresh_token: rt,
            grant_type: 'refresh_token',
          })
          .type('form')
          .expect(200), // one of them will fail.
      ]), () => {
        assert.equal(grantRevokeSpy.calledOnce, true);
        assert.equal(tokenDestroySpy.calledOnce, true);
        return true;
      });
    });
  });

  describe('rotateRefreshToken is a function (returns true)', () => {
    const fixture4 = Object.create(fixture);

    beforeEach(() => {
      i(fixture4.provider).configuration.rotateRefreshToken = sinon.mock().returns(true);
    }, { timeout: 3000 });

    afterEach(() => {
      const spy = i(fixture4.provider).configuration.rotateRefreshToken;
      i(fixture4.provider).configuration.rotateRefreshToken = false;
      assert.equal(spy.calledOnce, true);
    }, { timeout: 3000 });

    it('populates ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
      fixture4.assertOnce((ctx) => {
        assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Account', 'Grant', 'Client', 'AccessToken', 'RotatedRefreshToken', 'RefreshToken']));
        assert.notDeepEqual(ctx.oidc.entities.RotatedRefreshToken, ctx.oidc.entities.RefreshToken);
        ((actual) => { assert.ok('gty' in Object(actual)); assert.equal(actual.gty, 'authorization_code'); })(ctx.oidc.entities.RotatedRefreshToken);
        ((actual) => { assert.ok('gty' in Object(actual)); assert.equal(actual.gty, 'authorization_code refresh_token'); })(ctx.oidc.entities.RefreshToken);
        ((actual) => { assert.ok('gty' in Object(actual)); assert.equal(actual.gty, 'authorization_code refresh_token'); })(ctx.oidc.entities.AccessToken);
      }, done);

      fixture4.agent.post(route)
        .auth('client', 'secret')
        .send({
          refresh_token: fixture4.rt,
          grant_type: 'refresh_token',
        })
        .type('form')
        .end(() => {});
    });

    it('issues a new refresh token and consumes the old one', { timeout: 3000 }, () => {
      const { rt } = fixture4;
      const consumeSpy = sinon.spy();
      const issueSpy = sinon.spy();
      fixture4.provider.on('refresh_token.consumed', consumeSpy);
      fixture4.provider.on('refresh_token.saved', issueSpy);

      return fixture4.agent.post(route)
        .auth('client', 'secret')
        .send({
          refresh_token: rt,
          grant_type: 'refresh_token',
        })
        .type('form')
        .expect(200)
        .expect(() => {
          assert.equal(consumeSpy.calledOnce, true);
          assert.equal(issueSpy.called, true);
        })
        .expect((response) => {
          assert.deepEqual(new Set(Object.keys(response.body)), new Set(['access_token', 'id_token', 'expires_in', 'token_type', 'refresh_token', 'scope']));
          const refreshIdToken = JSON.parse(base64url.decode(response.body.id_token.split('.')[1]));
          ((actual) => { assert.ok('nonce' in Object(actual)); assert.equal(actual.nonce, 'foobarnonce'); })(refreshIdToken);
          ((actual) => { assert.ok('refresh_token' in Object(actual)); assert.notEqual(actual.refresh_token, rt); })(response.body);
        });
    });

    it('the new refresh token has identical scope to the old one', { timeout: 3000 }, () => {
      const { rt } = fixture4;
      const consumeSpy = sinon.spy();
      const issueSpy = sinon.spy();
      fixture4.provider.on('refresh_token.consumed', consumeSpy);
      fixture4.provider.on('refresh_token.saved', issueSpy);

      return fixture4.agent.post(route)
        .auth('client', 'secret')
        .send({
          refresh_token: rt,
          grant_type: 'refresh_token',
        })
        .type('form')
        .expect(200)
        .expect(() => {
          assert.equal(consumeSpy.calledOnce, true);
          assert.equal(issueSpy.called, true);
          ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, 'openid email offline_access'); })(consumeSpy.firstCall.args[0]);
          ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, 'openid email offline_access'); })(issueSpy.firstCall.args[0]);
        });
    });

    it('the new refresh token has identical scope to the old one even if the access token is requested with less scopes', { timeout: 3000 }, () => {
      const { rt } = fixture4;
      const consumeSpy = sinon.spy();
      const issueSpy = sinon.spy();
      fixture4.provider.on('refresh_token.consumed', consumeSpy);
      fixture4.provider.on('refresh_token.saved', issueSpy);
      fixture4.provider.on('access_token.saved', issueSpy);
      fixture4.provider.on('access_token.issued', issueSpy);

      return fixture4.agent.post(route)
        .auth('client', 'secret')
        .send({
          refresh_token: rt,
          scope: 'openid',
          grant_type: 'refresh_token',
        })
        .type('form')
        .expect(200)
        .expect(() => {
          assert.equal(consumeSpy.calledOnce, true);
          assert.equal(issueSpy.calledTwice, true);
          ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, 'openid email offline_access'); })(consumeSpy.firstCall.args[0]);
          ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, 'openid email offline_access'); })(issueSpy.firstCall.args[0]);
          ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, 'openid'); })(issueSpy.secondCall.args[0]);
        });
    });

    it('revokes the complete grant if the old token is used again', { timeout: 3000 }, () => {
      const { rt } = fixture4;

      const grantRevokeSpy = sinon.spy();
      const tokenDestroySpy = sinon.spy();
      fixture4.provider.on('grant.revoked', grantRevokeSpy);
      fixture4.provider.on('refresh_token.destroyed', tokenDestroySpy);

      return assert.rejects(Promise.all([
        fixture4.agent.post(route)
          .auth('client', 'secret')
          .send({
            refresh_token: rt,
            grant_type: 'refresh_token',
          })
          .type('form')
          .expect(200), // one of them will fail.
        fixture4.agent.post(route)
          .auth('client', 'secret')
          .send({
            refresh_token: rt,
            grant_type: 'refresh_token',
          })
          .type('form')
          .expect(200), // one of them will fail.
      ]), () => {
        assert.equal(grantRevokeSpy.calledOnce, true);
        assert.equal(tokenDestroySpy.calledOnce, true);
        return true;
      });
    });
  });

  describe('rotateRefreshToken is a function (returns false)', () => {
    const fixture5 = Object.create(fixture);

    beforeEach(() => {
      i(fixture5.provider).configuration.rotateRefreshToken = sinon.mock().returns(false);
    }, { timeout: 3000 });

    afterEach(() => {
      const spy = i(fixture5.provider).configuration.rotateRefreshToken;
      i(fixture5.provider).configuration.rotateRefreshToken = false;
      assert.equal(spy.calledOnce, true);
    }, { timeout: 3000 });

    it('does not rotate', { timeout: 3000 }, (_t, done) => {
      fixture5.assertOnce((ctx) => {
        assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Account', 'Grant', 'Client', 'AccessToken', 'RefreshToken']));
        ((actual) => { assert.ok('gty' in Object(actual)); assert.equal(actual.gty, 'authorization_code'); })(ctx.oidc.entities.RefreshToken);
        ((actual) => { assert.ok('gty' in Object(actual)); assert.equal(actual.gty, 'authorization_code refresh_token'); })(ctx.oidc.entities.AccessToken);
      }, done);

      fixture5.agent.post(route)
        .auth('client', 'secret')
        .send({
          refresh_token: fixture5.rt,
          grant_type: 'refresh_token',
        })
        .type('form')
        .expect(200)
        .expect(({ body }) => {
          assert.deepEqual(new Set(Object.keys(body)), new Set(['access_token', 'id_token', 'expires_in', 'token_type', 'refresh_token', 'scope']));
          const refreshIdToken = JSON.parse(base64url.decode(body.id_token.split('.')[1]));
          ((actual) => { assert.ok('nonce' in Object(actual)); assert.equal(actual.nonce, 'foobarnonce'); })(refreshIdToken);
          ((actual) => { assert.ok('refresh_token' in Object(actual)); assert.equal(typeof actual.refresh_token, 'string'); })(body);
        })
        .end(() => {});
    });
  });
});
