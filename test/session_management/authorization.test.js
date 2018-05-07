const bootstrap = require('../test_helper');
const sinon = require('sinon');
const crypto = require('crypto');
const { expect } = require('chai');
const { URL } = require('url');
const { config, client } = require('./session_management.config.js');

const route = '/auth';

describe('session management', () => {
  before(bootstrap(__dirname)); // provider, agent, this.AuthorizationRequest, wrap

  ['get', 'post'].forEach((verb) => {
    describe(`[session_management] ${verb} ${route} with session`, () => {
      before(function () { return this.login(); });

      it('provides session_state in the response', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validatePresence(['session_state'], false))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);
      });

      it('sets a _state.clientId cookies', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
        });

        return this.wrap({ route, verb, auth })
          .expect(() => {
            const state = this.agent.jar.getCookie('_state.client', { path: '/' });
            expect(state).to.be.ok;
          });
      });
    });

    describe('[session_management] check_session_iframe', () => {
      before(function () {
        this.provider.use(async (ctx, next) => {
          ctx.response.set('X-Frame-Options', 'SAMEORIGIN');
          ctx.response.set('Content-Security-Policy', "default-src 'none'; frame-ancestors 'self' example.com *.example.net; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';");
          await next();
        });
      });

      it('responds with frameable html', function () {
        return this.agent.get('/session/check')
          .expect(200)
          .expect('content-type', /text\/html/)
          .expect((response) => {
            expect(response.headers['x-frame-options']).not.to.be.ok;
            expect(response.headers['content-security-policy']).not.to.match(/frame-ancestors/);
          });
      });

      it('does not populate ctx.oidc.entities', function (done) {
        this.provider.use(this.assertOnce((ctx) => {
          expect(ctx.oidc.entities).to.be.empty;
        }, done));

        this.agent.get('/session/check').end(() => {});
      });
    });
  });

  describe('[session_management] session_state calculation', () => {
    function expected(url, salt) {
      const textToHash = `client ${url} 1525771507 ${salt}`;
      return crypto.createHash('sha256').update(textToHash).digest('hex');
    }

    before(function () {
      this.clock = sinon.useFakeTimers(new Date(1525771507000));
      return this.login();
    });

    after(function () {
      this.clock.restore();
    });

    it('calculates session_state using redirect_uri', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      return this.agent.get('/auth').query(auth)
        .expect((response) => {
          const redirectUrl = new URL(response.headers.location);
          const sessionState = redirectUrl.searchParams.get('session_state');
          const [sessionStr, salt] = sessionState.split('.');
          expect(sessionStr).to.equal(expected('https://client.example.com', salt));
        });
    });

    it('calculates session_state using redirect_uri with port', async () => {
      const { redirect_uris } = client;
      client.redirect_uris = ['https://client.example.com:8080/cb'];
      await bootstrap(__dirname).call(this);
      await this.login();
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      return this.agent.get('/auth').query(auth)
        .expect((response) => {
          client.redirect_uris = redirect_uris;
          const redirectUrl = new URL(response.headers.location);
          const sessionState = redirectUrl.searchParams.get('session_state');
          const [sessionStr, salt] = sessionState.split('.');
          expect(sessionStr).to.equal(expected('https://client.example.com:8080', salt));
        });
    });

    context('when minDomainAtoms', () => {
      it('calculates session_state using redirect_uri', async () => {
        const { features: { sessionManagement } } = config;
        config.features.sessionManagement = { minDomainAtoms: 2 };
        await bootstrap(__dirname).call(this);
        await this.login();
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
        });

        return this.agent.get('/auth').query(auth)
          .expect((response) => {
            config.features.sessionManagement = sessionManagement;
            const redirectUrl = new URL(response.headers.location);
            const sessionState = redirectUrl.searchParams.get('session_state');
            const [sessionStr, salt] = sessionState.split('.');
            expect(sessionStr).to.equal(expected('https://example.com', salt));
          });
      });

      it('fallbacks to full uri when domain has less atoms', async () => {
        const { features: { sessionManagement } } = config;
        config.features.sessionManagement = { minDomainAtoms: 42 };
        await bootstrap(__dirname).call(this);
        await this.login();
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
        });

        return this.agent.get('/auth').query(auth)
          .expect((response) => {
            config.features.sessionManagement = sessionManagement;
            const redirectUrl = new URL(response.headers.location);
            const sessionState = redirectUrl.searchParams.get('session_state');
            const [sessionStr, salt] = sessionState.split('.');
            expect(sessionStr).to.equal(expected('https://client.example.com', salt));
          });
      });
    });
  });
});
