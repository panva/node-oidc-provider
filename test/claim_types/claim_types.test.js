import { describe, before, after, it } from 'node:test';
import assert from 'node:assert/strict';
import { parse as parseLocation } from 'node:url';


import bootstrap from '../test_helper.js';
import { decode as decodeJWT } from '../../lib/helpers/jwt.js';

describe('distributed and aggregated claims', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });
  before(() => {
    i(fixture.provider).configuration.findAccount = (_ctx, id) => Promise.resolve({
      accountId: id,
      claims() {
        return {
          sub: id,
          nickname: 'foobar',
          _claim_names: {
            given_name: 'src1',
            family_name: 'src2',
            email: 'notused',
          },
          _claim_sources: {
            src1: { endpoint: 'https://op.example.com/me', access_token: 'distributed' },
            src2: { JWT: 'foo.bar.baz' },
            notused: { JWT: 'foo.bar.baz' },
          },
        };
      },
    });
  }, { timeout: 3000 });

  before(() => fixture.login({ scope: 'openid profile' }), { timeout: 3000 });
  after(() => fixture.logout(), { timeout: 3000 });

  describe('id_token', () => {
    const fixture1 = Object.create(fixture);

    it('should return _claim_names and _claim_sources members', { timeout: 3000 }, () => {
      const auth = new fixture1.AuthorizationRequest({
        response_type: 'id_token',
        scope: 'openid profile',
      });

      return fixture1.wrap({ auth, route: '/auth', verb: 'get' })
        .expect(auth.validateFragment)
        .expect((response) => {
          const { query: { id_token } } = parseLocation(response.headers.location, true);
          const { payload } = decodeJWT(id_token);

          ((actual) => { assert.ok('nickname' in Object(actual)); assert.equal(actual.nickname, 'foobar'); })(payload);
          assert.ok(!('given_name' in Object(payload)));

          assert.ok('_claim_names' in Object(payload));
          assert.ok('_claim_sources' in Object(payload));

          assert.deepEqual(new Set(Object.keys(payload._claim_names)), new Set(['given_name', 'family_name']));
          assert.deepEqual(new Set(Object.keys(payload._claim_sources)), new Set(['src1', 'src2']));
        });
    });

    it('does not return the members if these claims arent requested at all', { timeout: 3000 }, () => {
      const auth = new fixture1.AuthorizationRequest({
        response_type: 'id_token',
        scope: 'openid',
      });

      return fixture1.wrap({ auth, route: '/auth', verb: 'get' })
        .expect(auth.validateFragment)
        .expect((response) => {
          const { query: { id_token } } = parseLocation(response.headers.location, true);
          const { payload } = decodeJWT(id_token);

          assert.ok(!('_claim_names' in Object(payload)));
          assert.ok(!('_claim_sources' in Object(payload)));
        });
    });
  });

  describe('userinfo', () => {
    const fixture2 = Object.create(fixture);

    it('should return _claim_names and _claim_sources members', { timeout: 3000 }, (_t, done) => {
      const auth = new fixture2.AuthorizationRequest({
        response_type: 'id_token token',
        scope: 'openid profile',
      });

      fixture2.wrap({ auth, route: '/auth', verb: 'get' })
        .expect(auth.validateFragment)
        .end((error, authorization) => {
          if (error) return done(error);

          const { query: { access_token } } = parseLocation(authorization.headers.location, true);

          return fixture2.agent.get('/me')
            .auth(access_token, { type: 'bearer' })
            .expect(200)
            .end((userinfoError, userinfo) => {
              if (userinfoError) return done(userinfoError);

              const payload = userinfo.body;

              ((actual) => { assert.ok('nickname' in Object(actual)); assert.equal(actual.nickname, 'foobar'); })(payload);
              assert.ok(!('given_name' in Object(payload)));

              assert.ok('_claim_names' in Object(payload));
              assert.ok('_claim_sources' in Object(payload));

              assert.deepEqual(new Set(Object.keys(payload._claim_names)), new Set(['given_name', 'family_name']));
              assert.deepEqual(new Set(Object.keys(payload._claim_sources)), new Set(['src1', 'src2']));

              return done();
            });
        });
    });

    it('does not return the members if these claims arent requested at all', { timeout: 3000 }, (_t, done) => {
      const auth = new fixture2.AuthorizationRequest({
        response_type: 'id_token token',
        scope: 'openid',
      });

      fixture2.wrap({ auth, route: '/auth', verb: 'get' })
        .expect(auth.validateFragment)
        .end((error, authorization) => {
          if (error) return done(error);

          const { query: { access_token } } = parseLocation(authorization.headers.location, true);

          return fixture2.agent.get('/me')
            .auth(access_token, { type: 'bearer' })
            .expect(200)
            .end((userinfoError, userinfo) => {
              if (userinfoError) return done(userinfoError);

              const payload = userinfo.body;

              assert.ok(!('_claim_names' in Object(payload)));
              assert.ok(!('_claim_sources' in Object(payload)));

              return done();
            });
        });
    });
  });
});
