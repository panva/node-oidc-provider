'use strict';

/* eslint-disable no-underscore-dangle */

const {
  provider,
  agent,
  AuthorizationRequest,
  wrap
} = require('../test_helper')(__dirname);
const { parse: parseLocation } = require('url');
const { decode: decodeJWT } = require('../../lib/helpers/jwt');
const { expect } = require('chai');

provider.setupClient();
provider.setupCerts();

const Account = provider.get('Account');

Account.findById = id => Promise.resolve({
  accountId: id,
  claims() {
    return {
      sub: id,
      nickname: 'foobar',
      _claim_names: {
        given_name: 'src1',
        family_name: 'src2',
        email: 'notused'
      },
      _claim_sources: {
        src1: { endpoint: 'https://op.example.com/me', access_token: 'distributed' },
        src2: { JWT: 'foo.bar.baz' },
        notused: { JWT: 'foo.bar.baz' }
      },
    };
  },
});

describe('distributed and aggregated claims', function () {
  before(agent.login);
  after(agent.logout);

  context('id_token', function () {
    it('should return _claim_names and _claim_sources members', function () {
      const auth = new AuthorizationRequest({
        response_type: 'id_token token',
        scope: 'openid profile'
      });

      return wrap({ agent, auth, route: '/auth', verb: 'get' })
      .expect(auth.validateFragment)
      .expect(function (response) {
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
      const auth = new AuthorizationRequest({
        response_type: 'id_token token',
        scope: 'openid'
      });

      return wrap({ agent, auth, route: '/auth', verb: 'get' })
      .expect(auth.validateFragment)
      .expect(function (response) {
        const { query: { id_token } } = parseLocation(response.headers.location, true);
        const { payload } = decodeJWT(id_token);

        expect(payload).not.to.have.property('_claim_names');
        expect(payload).not.to.have.property('_claim_sources');
      });
    });
  });

  context('userinfo', function () {
    it('should return _claim_names and _claim_sources members', function (done) {
      const auth = new AuthorizationRequest({
        response_type: 'id_token token',
        scope: 'openid profile'
      });

      wrap({ agent, auth, route: '/auth', verb: 'get' })
      .expect(auth.validateFragment)
      .end(function (error, authorization) {
        if (error) return done(error);

        const { query: { access_token } } = parseLocation(authorization.headers.location, true);

        return agent.get('/me')
          .query({ access_token })
          .expect(200)
          .end(function (userinfoError, userinfo) {
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
      const auth = new AuthorizationRequest({
        response_type: 'id_token token',
        scope: 'openid'
      });

      wrap({ agent, auth, route: '/auth', verb: 'get' })
      .expect(auth.validateFragment)
      .end(function (error, authorization) {
        if (error) return done(error);

        const { query: { access_token } } = parseLocation(authorization.headers.location, true);

        return agent.get('/me')
          .query({ access_token })
          .expect(200)
          .end(function (userinfoError, userinfo) {
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
