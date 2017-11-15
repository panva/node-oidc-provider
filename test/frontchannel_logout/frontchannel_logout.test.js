const bootstrap = require('../test_helper');
const { expect } = require('chai');
const { parse: parseUrl } = require('url');
const url = require('url');
const base64url = require('base64url');
const Provider = require('../../lib');

describe('Front-Channel Logout 1.0', () => {
  before(bootstrap(__dirname));

  describe('feature flag', () => {
    it('checks sessionManagement is also enabled', () => {
      expect(() => {
        new Provider('http://localhost', { // eslint-disable-line no-new
          features: {
            frontchannelLogout: true,
          },
        });
      }).to.throw('frontchannelLogout is only available in conjuction with sessionManagement');
    });
  });

  describe('discovery extension', () => {
    it('extends the well known config', function () {
      return this.agent.get('/.well-known/openid-configuration')
        .expect((response) => {
          expect(response.body).to.have.property('frontchannel_logout_supported', true);
          expect(response.body).to.have.property('frontchannel_logout_session_supported', true);
        });
    });
  });

  describe('end_session extension', () => {
    beforeEach(function () { return this.login(); });
    afterEach(function () { return this.logout(); });

    beforeEach(function () {
      return this.agent.get('/auth')
        .query({
          client_id: 'client',
          scope: 'openid',
          nonce: String(Math.random()),
          response_type: 'code id_token',
          redirect_uri: 'https://client.example.com/cb',
        })
        .expect(302)
        .expect((response) => {
          const { query: { code, id_token: idToken } } = parseUrl(response.headers.location.replace('#', '?'), true);
          this.idToken = idToken;
          this.code = code;
        });
    });

    it('makes sid available in id_token issued by authorization endpoint', function () {
      const payload = JSON.parse(base64url.decode(this.idToken.split('.')[1]));
      expect(payload).to.have.property('sid').that.is.a('string');
    });

    it('makes sid available in id_token issued by grant_type=authorization_code', function () {
      return this.agent.post('/token')
        .auth('client', 'secret')
        .type('form')
        .send({
          code: this.code,
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.com/cb',
        })
        .expect(200)
        .expect((response) => {
          const payload = JSON.parse(base64url.decode(response.body.id_token.split('.')[1]));
          expect(payload).to.have.property('sid').that.is.a('string');
        });
    });

    it('makes sid available in id_token issued by grant_type=refresh_token', function (done) {
      this.agent.post('/token')
        .auth('client', 'secret')
        .type('form')
        .send({
          code: this.code,
          grant_type: 'authorization_code',
          redirect_uri: 'https://client.example.com/cb',
        })
        .expect(200)
        .end((error, acResponse) => {
          if (error) { done(error); return; }
          this.agent.post('/token')
            .auth('client', 'secret')
            .type('form')
            .send({
              refresh_token: acResponse.body.refresh_token,
              grant_type: 'refresh_token',
            })
            .expect(200)
            .expect((rtResponse) => {
              const payload = JSON.parse(base64url.decode(rtResponse.body.id_token.split('.')[1]));
              expect(payload).to.have.property('sid').that.is.a('string');
            })
            .end(done);
        });
    });

    it('triggers the backchannelLogout for visited clients', async function () {
      const session = this.getSession();
      session.logout = { secret: '123', postLogoutRedirectUri: '/' };
      const params = { logout: 'yes', xsrf: '123' };

      const { sid } = session.authorizations.client;
      const client = await this.provider.Client.find('client');

      return this.agent.post('/session/end')
        .send(params)
        .type('form')
        .expect(200)
        .expect('content-type', /^text\/html;/)
        .expect(({ text: body }) => {
          expect(body).to.match(new RegExp('<iframe src="(.+)"></iframe>'));
          const { query, href } = url.parse(RegExp.$1, true);
          expect(query).to.have.property('iss', this.provider.issuer);
          expect(query).to.have.property('sid', sid);
          expect(href.startsWith(`${client.frontchannelLogoutUri}?`)).to.be.true;
        });
    });

    it('ignores the backchannelLogout when client does not support', async function () {
      this.getSession().logout = { secret: '123', postLogoutRedirectUri: '/' };
      const params = { logout: 'yes', xsrf: '123' };
      const client = await this.provider.Client.find('client');
      delete client.frontchannelLogoutUri;

      return this.agent.post('/session/end')
        .send(params)
        .type('form')
        .expect(302);
    });
  });
});
