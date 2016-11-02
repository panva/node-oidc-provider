'use strict';

const bootstrap = require('../test_helper');
const sinon = require('sinon');
const { expect } = require('chai');
const { parse: parseUrl } = require('url');
const base64url = require('base64url');
const nock = require('nock');
const { Provider } = require('../../lib');

describe('Back-Channel Logout 1.0', function () {
  before(bootstrap(__dirname));

  afterEach(nock.cleanAll);
  afterEach(function* () {
    const client = yield this.provider.Client.find('client');
    if (client.backchannelLogout.restore) client.backchannelLogout.restore();
  });

  describe('feature flag', function () {
    it('checks sessionManagement is also enabled', function () {
      expect(() => {
        new Provider('http://localhost', { // eslint-disable-line no-new
          features: {
            backchannelLogout: true
          }
        });
      }).to.throw('backchannelLogout is only available in conjuction with sessionManagement');
    });
  });

  describe('Client#backchannelLogout', function () {
    it('triggers the call, does not return values', function* () {
      const client = yield this.provider.Client.find('client');

      nock('https://client.example.com/')
        .filteringRequestBody((body) => {
          expect(body).to.match(/^logout_token=(([\w-]+\.?){3})$/);
          const decoded = JSON.parse(base64url.decode(RegExp.$1.split('.')[1]));
          expect(decoded).to.have.all.keys('sub', 'events', 'iat', 'aud', 'iss', 'jti');
          expect(decoded).to.have.property('events').and.eql(['http://schemas.openid.net/event/backchannel-logout']);
          expect(decoded).to.have.property('aud', 'client');
          expect(decoded).to.have.property('sub', 'subject');
        })
        .post('/backchannel_logout')
        .reply(204);

      return client.backchannelLogout('subject').then((result) => {
        expect(result).to.be.undefined;
        expect(nock.isDone()).to.be.true;
      });
    });

    it('does ignore request and sig errors', function* () {
      const client = yield this.provider.Client.find('client');

      // not defining the nock scope makes the request part throw
      return client.backchannelLogout('subject').catch(() => {
        throw new Error('expected promise to be resolved');
      });
    });
  });

  describe('discovery extension', function () {
    it('extends the well known config', function () {
      return this.agent.get('/.well-known/openid-configuration')
      .expect((response) => {
        expect(response.body).to.have.property('backchannel_logout_supported', true);
        expect(response.body).to.have.property('backchannel_logout_session_supported', true);
      });
    });
  });

  describe('end_session extension', function () {
    beforeEach(function () { return this.login(); });
    afterEach(function () { return this.logout(); });

    beforeEach(function () {
      return this.agent.get('/auth')
      .query({
        client_id: 'client',
        scope: 'openid',
        nonce: String(Math.random()),
        response_type: 'code id_token',
        redirect_uri: 'https://client.example.com/cb'
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
          redirect_uri: 'https://client.example.com/cb'
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
          redirect_uri: 'https://client.example.com/cb'
        })
        .expect(200)
        .end((error, acResponse) => {
          if (error) { done(error); return; }
          this.agent.post('/token')
            .auth('client', 'secret')
            .type('form')
            .send({
              refresh_token: acResponse.body.refresh_token,
              grant_type: 'refresh_token'
            })
            .expect(200)
            .expect((rtResponse) => {
              const payload = JSON.parse(base64url.decode(rtResponse.body.id_token.split('.')[1]));
              expect(payload).to.have.property('sid').that.is.a('string');
            })
            .end(done);
        });
    });

    it('triggers the backchannelLogout for visited clients', function* () {
      const session = this.getSession(this.agent);
      session.logout = { secret: '123', postLogoutRedirectUri: '/' };
      const params = { logout: 'yes', xsrf: '123' };
      const client = yield this.provider.Client.find('client');

      sinon.spy(client, 'backchannelLogout');

      const accountId = session.account;
      const sid = session.authorizations.client.sid;

      return this.agent.post('/session/end')
      .send(params)
      .type('form')
      .expect(302)
      .expect(() => {
        expect(client.backchannelLogout.called).to.be.true;
        expect(client.backchannelLogout.calledWith(accountId, sid)).to.be.true;
        client.backchannelLogout.restore();
      });
    });

    it('ignores the backchannelLogout when client does not support', function* () {
      this.getSession(this.agent).logout = { secret: '123', postLogoutRedirectUri: '/' };
      const params = { logout: 'yes', xsrf: '123' };
      const client = yield this.provider.Client.find('client');
      delete client.backchannelLogoutUri;

      sinon.spy(client, 'backchannelLogout');

      return this.agent.post('/session/end')
      .send(params)
      .type('form')
      .expect(302)
      .expect(() => {
        expect(client.backchannelLogout.called).to.be.false;
        client.backchannelLogout.restore();
      });
    });
  });
});
