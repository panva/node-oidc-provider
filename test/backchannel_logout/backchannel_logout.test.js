const { parse: parseUrl } = require('url');

const sinon = require('sinon').createSandbox();
const { expect } = require('chai');
const base64url = require('base64url');
const nock = require('nock');

const bootstrap = require('../test_helper');

const fail = () => { throw new Error('expected promise to be rejected'); };

describe('Back-Channel Logout 1.0', () => {
  before(bootstrap(__dirname));

  afterEach(nock.cleanAll);
  afterEach(sinon.restore);

  describe('Client#backchannelLogout', () => {
    it('triggers the call', async function () {
      const client = await this.provider.Client.find('client');

      nock('https://client.example.com/')
        .filteringRequestBody((body) => {
          expect(body).to.match(/^logout_token=(([\w-]+\.?){3})$/);
          const decoded = JSON.parse(base64url.decode(RegExp.$1.split('.')[1]));
          expect(decoded).to.have.all.keys('sub', 'events', 'iat', 'aud', 'iss', 'jti', 'sid');
          expect(decoded).to.have.property('events').and.eql({ 'http://schemas.openid.net/event/backchannel-logout': {} });
          expect(decoded).to.have.property('aud', 'client');
          expect(decoded).to.have.property('sub', 'subject');
          expect(decoded).to.have.property('sid', 'foo');
        })
        .post('/backchannel_logout', () => true)
        .reply(200);

      return client.backchannelLogout('subject', 'foo');
    });

    it('uses custom http options when provided', async function () {
      const client = await this.provider.Client.find('client');

      const pre = i(this.provider).configuration('httpOptions');
      i(this.provider).configuration().httpOptions = (opts) => {
        Object.assign(opts.body, { foo: 'bar' });
        return opts;
      };

      nock('https://client.example.com/')
        .filteringRequestBody((body) => {
          expect(body).to.match(/^logout_token=(([\w-]+\.?){3})&foo=bar$/);
        })
        .post('/backchannel_logout', () => true)
        .reply(200);

      return client.backchannelLogout('subject', 'foo').then(() => {
        i(this.provider).configuration().httpOptions = pre;
      });
    });

    it('omits sid when its not required', async function () {
      const client = await this.provider.Client.find('no-sid');

      nock('https://no-sid.example.com/')
        .filteringRequestBody((body) => {
          expect(body).to.match(/^logout_token=(([\w-]+\.?){3})$/);
          const decoded = JSON.parse(base64url.decode(RegExp.$1.split('.')[1]));
          expect(decoded).to.have.all.keys('sub', 'events', 'iat', 'aud', 'iss', 'jti');
          expect(decoded).to.have.property('events').and.eql({ 'http://schemas.openid.net/event/backchannel-logout': {} });
          expect(decoded).to.have.property('aud', 'no-sid');
          expect(decoded).to.have.property('sub', 'subject');
          expect(decoded).not.to.have.property('sid');
        })
        .post('/backchannel_logout', () => true)
        .reply(200);

      return client.backchannelLogout('subject', 'foo');
    });

    it('handles non-200 OK responses', async function () {
      const client = await this.provider.Client.find('no-sid');

      nock('https://no-sid.example.com/')
        .post('/backchannel_logout')
        .reply(500);

      return client.backchannelLogout('subject', 'foo').then(fail, (err) => {
        expect(err.message).to.eql('expected 200 OK from https://no-sid.example.com/backchannel_logout, got: 500 Internal Server Error');
      });
    });
  });

  describe('discovery', () => {
    it('extends the well known config', function () {
      return this.agent.get('/.well-known/openid-configuration')
        .expect((response) => {
          expect(response.body).to.have.property('end_session_endpoint');
          expect(response.body).to.have.property('backchannel_logout_supported', true);
          expect(response.body).to.have.property('backchannel_logout_session_supported', true);
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
          const { query } = parseUrl(response.headers.location.replace('#', '?'), true);
          expect(query).to.have.property('code');
          expect(query).to.have.property('id_token');
          this.idToken = query.id_token;
          this.code = query.code;
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

    it('triggers the backchannelLogout for all visited clients [when global logout]', async function () {
      const session = this.getSession();
      session.state = { secret: '123', clientId: 'client', postLogoutRedirectUri: '/' };
      const params = { logout: 'yes', xsrf: '123' };
      const client = await this.provider.Client.find('client');
      const client2 = await this.provider.Client.find('second-client');

      sinon.spy(client, 'backchannelLogout');
      sinon.spy(client2, 'backchannelLogout');

      nock('https://client.example.com/')
        .post('/backchannel_logout')
        .reply(200);

      const successSpy = sinon.spy();
      this.provider.once('backchannel.success', successSpy);
      const errorSpy = sinon.spy();
      this.provider.once('backchannel.error', errorSpy);

      const accountId = session.account;

      return this.agent.post('/session/end/confirm')
        .send(params)
        .type('form')
        .expect(302)
        .expect(() => {
          (() => {
            const { sid } = session.authorizations.client;
            expect(client.backchannelLogout.called).to.be.true;
            expect(client.backchannelLogout.calledWith(accountId, sid)).to.be.true;
            client.backchannelLogout.restore();
            expect(successSpy.calledOnce).to.be.true;
          })();
          (() => {
            const { sid } = session.authorizations['second-client'];
            expect(client2.backchannelLogout.called).to.be.true;
            expect(client2.backchannelLogout.calledWith(accountId, sid)).to.be.true;
            client2.backchannelLogout.restore();
            expect(errorSpy.calledOnce).to.be.true;
          })();
        });
    });

    it('still triggers the backchannelLogout for the specific client [when no global logout]', async function () {
      const session = this.getSession();
      session.state = { secret: '123', clientId: 'client', postLogoutRedirectUri: '/' };
      const params = { xsrf: '123' };
      const client = await this.provider.Client.find('client');
      const client2 = await this.provider.Client.find('second-client');

      sinon.spy(client, 'backchannelLogout');
      sinon.spy(client2, 'backchannelLogout');

      const accountId = session.account;
      const { sid } = session.authorizations.client;

      return this.agent.post('/session/end/confirm')
        .send(params)
        .type('form')
        .expect(302)
        .expect(() => {
          expect(client.backchannelLogout.called).to.be.true;
          expect(client.backchannelLogout.calledWith(accountId, sid)).to.be.true;
          client.backchannelLogout.restore();
          expect(client2.backchannelLogout.called).to.be.false;
          client2.backchannelLogout.restore();
        });
    });

    it('ignores the backchannelLogout when client does not support', async function () {
      this.getSession().state = { secret: '123', clientId: 'client', postLogoutRedirectUri: '/' };
      const params = { logout: 'yes', xsrf: '123' };
      const client = await this.provider.Client.find('client');
      const client2 = await this.provider.Client.find('second-client');
      delete client.backchannelLogoutUri;

      sinon.spy(client, 'backchannelLogout');
      sinon.spy(client2, 'backchannelLogout');

      return this.agent.post('/session/end/confirm')
        .send(params)
        .type('form')
        .expect(302)
        .expect(() => {
          expect(client.backchannelLogout.called).to.be.false;
          client.backchannelLogout.restore();
          expect(client2.backchannelLogout.called).to.be.true;
        });
    });
  });
});
