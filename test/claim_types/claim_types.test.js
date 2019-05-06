/* eslint-disable no-underscore-dangle */

const { parse: parseLocation } = require('url');

const { expect } = require('chai');

const bootstrap = require('../test_helper');
const { decode: decodeJWT } = require('../../lib/helpers/jwt');

describe('distributed and aggregated claims', () => {
  before(bootstrap(__dirname));
  before(function () {
    const { Account } = this.provider;
    Account.findAccount = (ctx, id) => Promise.resolve({
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
  });

  before(function () { return this.login({ scope: 'openid profile' }); });
  after(function () { return this.logout(); });

  context('id_token', () => {
    it('should return _claim_names and _claim_sources members', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'id_token',
        scope: 'openid profile',
      });

      return this.wrap({ auth, route: '/auth', verb: 'get' })
        .expect(auth.validateFragment)
        .expect((response) => {
          const { query: { id_token } } = parseLocation(response.headers.location, true);
          const { payload } = decodeJWT(id_token);

          expect(payload).to.have.property('nickname', 'foobar');
          expect(payload).not.to.have.property('given_name');

          expect(payload).to.have.property('_claim_names');
          expect(payload).to.have.property('_claim_sources');

          expect(payload._claim_names).to.have.keys('given_name', 'family_name');
          expect(payload._claim_sources).to.have.keys('src1', 'src2');
        });
    });

    it('does not return the members if these claims arent requested at all', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'id_token',
        scope: 'openid',
      });

      return this.wrap({ auth, route: '/auth', verb: 'get' })
        .expect(auth.validateFragment)
        .expect((response) => {
          const { query: { id_token } } = parseLocation(response.headers.location, true);
          const { payload } = decodeJWT(id_token);

          expect(payload).not.to.have.property('_claim_names');
          expect(payload).not.to.have.property('_claim_sources');
        });
    });
  });

  context('userinfo', () => {
    it('should return _claim_names and _claim_sources members', function (done) {
      const auth = new this.AuthorizationRequest({
        response_type: 'id_token token',
        scope: 'openid profile',
      });

      this.wrap({ auth, route: '/auth', verb: 'get' })
        .expect(auth.validateFragment)
        .end((error, authorization) => {
          if (error) return done(error);

          const { query: { access_token } } = parseLocation(authorization.headers.location, true);

          return this.agent.get('/me')
            .query({ access_token })
            .expect(200)
            .end((userinfoError, userinfo) => {
              if (userinfoError) return done(userinfoError);

              const payload = userinfo.body;

              expect(payload).to.have.property('nickname', 'foobar');
              expect(payload).not.to.have.property('given_name');

              expect(payload).to.have.property('_claim_names');
              expect(payload).to.have.property('_claim_sources');

              expect(payload._claim_names).to.have.keys('given_name', 'family_name');
              expect(payload._claim_sources).to.have.keys('src1', 'src2');

              return done();
            });
        });
    });

    it('does not return the members if these claims arent requested at all', function (done) {
      const auth = new this.AuthorizationRequest({
        response_type: 'id_token token',
        scope: 'openid',
      });

      this.wrap({ auth, route: '/auth', verb: 'get' })
        .expect(auth.validateFragment)
        .end((error, authorization) => {
          if (error) return done(error);

          const { query: { access_token } } = parseLocation(authorization.headers.location, true);

          return this.agent.get('/me')
            .query({ access_token })
            .expect(200)
            .end((userinfoError, userinfo) => {
              if (userinfoError) return done(userinfoError);

              const payload = userinfo.body;

              expect(payload).not.to.have.property('_claim_names');
              expect(payload).not.to.have.property('_claim_sources');

              return done();
            });
        });
    });
  });
});
