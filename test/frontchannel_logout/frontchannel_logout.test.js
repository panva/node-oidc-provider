const { parse: parseUrl } = require('url');

const { expect } = require('chai');
const cloneDeep = require('lodash/cloneDeep');
const base64url = require('base64url');

const bootstrap = require('../test_helper');

describe('Front-Channel Logout 1.0', () => {
  before(bootstrap(__dirname));

  describe('discovery', () => {
    it('extends the well known config', function () {
      return this.agent.get('/.well-known/openid-configuration')
        .expect((response) => {
          expect(response.body).to.have.property('end_session_endpoint');
          expect(response.body).to.have.property('frontchannel_logout_supported', true);
          expect(response.body).to.have.property('frontchannel_logout_session_supported', true);
        });
    });
  });

  describe('end_session extension', () => {
    beforeEach(function () { return this.login(); });
    afterEach(function () { return this.logout(); });

    bootstrap.skipConsent();

    beforeEach(function () {
      return this.agent.get('/auth')
        .query({
          client_id: 'client',
          scope: 'openid offline_access',
          prompt: 'consent',
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

    it('triggers the frontchannelLogout for all visited clients [when global logout]', async function () {
      let session = this.getSession();
      session.state = { secret: '123', clientId: 'client', postLogoutRedirectUri: '/' };
      session = cloneDeep(session);
      const params = { logout: 'yes', xsrf: '123' };

      const client = await this.provider.Client.find('client');
      const client2 = await this.provider.Client.find('second-client');
      const client3 = await this.provider.Client.find('no-nothing');

      const FRAME = /<iframe src="([^"]+)"><\/iframe>/g;

      return this.agent.post('/session/end/confirm')
        .send(params)
        .type('form')
        .expect(200)
        .expect('content-type', /^text\/html;/)
        .expect(({ text: body }) => {
          expect(body.match(FRAME)).to.have.length(3);

          (() => {
            const { sid } = session.authorizations.client;
            const [, match] = FRAME.exec(body);
            const { query, href } = parseUrl(match, true);
            expect(query).to.have.property('iss', this.provider.issuer);
            expect(query).to.have.property('sid', sid);
            expect(href.startsWith(`${client.frontchannelLogoutUri}?`)).to.be.true;
          })();

          (() => {
            const { sid } = session.authorizations['second-client'];
            const [, match] = FRAME.exec(body);
            const { query, href } = parseUrl(match, true);
            expect(query).to.have.property('iss', this.provider.issuer);
            expect(query).to.have.property('sid', sid);
            expect(href.startsWith(`${client2.frontchannelLogoutUri}?`)).to.be.true;
          })();

          (() => {
            const [, match] = FRAME.exec(body);
            const { query, href } = parseUrl(match, true);
            expect(query).not.to.have.property('iss');
            expect(query).not.to.have.property('sid');
            expect(href).to.equal(client3.frontchannelLogoutUri);
          })();
        });
    });

    it('still triggers the frontchannelLogout for the specific client [when no global logout]', async function () {
      let session = this.getSession();
      session.state = { secret: '123', clientId: 'client', postLogoutRedirectUri: '/' };
      session = cloneDeep(session);
      const params = { xsrf: '123' };

      const client = await this.provider.Client.find('client');

      const FRAME = /<iframe src="([^"]+)"><\/iframe>/g;

      return this.agent.post('/session/end/confirm')
        .send(params)
        .type('form')
        .expect(200)
        .expect('content-type', /^text\/html;/)
        .expect(({ text: body }) => {
          expect(body.match(FRAME)).to.have.length(1);

          (() => {
            const { sid } = session.authorizations.client;
            const [, match] = FRAME.exec(body);
            const { query, href } = parseUrl(match, true);
            expect(query).to.have.property('iss', this.provider.issuer);
            expect(query).to.have.property('sid', sid);
            expect(href.startsWith(`${client.frontchannelLogoutUri}?`)).to.be.true;
          })();
        });
    });

    it('ignores the frontchannelLogout when client does not support it', async function () {
      this.getSession().state = { secret: '123', clientId: 'client', postLogoutRedirectUri: '/' };
      const params = { xsrf: '123' };
      const client = await this.provider.Client.find('client');
      delete client.frontchannelLogoutUri;

      return this.agent.post('/session/end/confirm')
        .send(params)
        .type('form')
        .expect(302);
    });
  });
});
