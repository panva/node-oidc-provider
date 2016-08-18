const { provider, agent } = require('../test_helper')(__dirname);
const sinon = require('sinon');
const { expect } = require('chai');
const { parse: parseUrl } = require('url');
const base64url = require('base64url');
const nock = require('nock');
const { Provider } = require('../../lib');

provider.setupCerts();
provider.setupClient();

describe('Back-Channel Logout 1.0', function () {
  afterEach(nock.cleanAll);
  afterEach(function * () {
    const client = yield provider.get('Client').find('client');
    if (client.backchannelLogout.restore) client.backchannelLogout.restore();
  });

  describe('feature flag', function () {
    it('checks sessionManagement is also enabled', function () {
      expect(function () {
        new Provider('http://localhost', { // eslint-disable-line no-new
          features: {
            backchannelLogout: true
          }
        });
      }).to.throw('backchannelLogout is only available in conjuction with sessionManagement');
    });
  });

  describe('Client#backchannelLogout', function () {
    // TODO: REDO, it's failing sometimes
    it('triggers the call, does not return values', function * () {
      const client = yield provider.get('Client').find('client');
      const now = Date.now() / 1000 | 0;

      nock('https://client.example.com/')
        .filteringRequestBody(function (body) {
          expect(body).to.match(/^logout_token=(([\w-]+\.?){3})$/);
          const decoded = JSON.parse(base64url.decode(RegExp.$1.split('.')[1]));
          expect(decoded).to.have.all.keys('sub', 'logout_only', 'iat', 'exp', 'aud', 'iss', 'jti');
          expect(decoded).to.have.property('logout_only', true);
          expect(decoded).to.have.property('aud', 'client');
          expect(decoded).to.have.property('sub', 'subject');
          expect(decoded).to.have.property('exp').to.be.at.most(now + 120);
        })
        .post('/backchannel_logout')
        .reply(204);

      return client.backchannelLogout('subject').then(result => {
        expect(result).to.be.undefined;
        expect(nock.isDone()).to.be.true;
      });
    });

    it('does ignore request and sig errors', function * () {
      const client = yield provider.get('Client').find('client');

      // not defining the nock scope makes the request part throw
      return client.backchannelLogout('subject').catch(function () {
        throw new Error('expected promise to be resolved');
      });
    });
  });

  describe('discovery extension', function () {
    it('extends the well known config', function () {
      return agent.get('/.well-known/openid-configuration')
      .expect(function (response) {
        expect(response.body).to.have.property('backchannel_logout_supported', true);
        expect(response.body).not.to.have.property('backchannel_logout_session_supported');
      });
    });
  });

  describe('end_session extension', function () {
    beforeEach(agent.login);
    afterEach(agent.logout);

    beforeEach(function () {
      return agent.get('/auth')
      .query({
        client_id: 'client',
        scope: 'openid',
        nonce: String(Math.random()),
        response_type: 'id_token',
        redirect_uri: 'https://client.example.com/cb'
      })
      .expect(302)
      .expect((response) => {
        const { query: { id_token: idToken } } = parseUrl(response.headers.location.replace('#', '?'), true);
        this.idToken = idToken;
      });
    });

    it('triggers the backchannelLogout for visited clients', function * () {
      const params = { id_token_hint: this.idToken };
      const client = yield provider.get('Client').find('client');

      sinon.spy(client, 'backchannelLogout');

      return agent.get('/session/end')
      .query(params)
      .expect(function () {
        expect(client.backchannelLogout.called).to.be.true;
        client.backchannelLogout.restore();
      });
    });

    it('ignores the backchannelLogout when client does not support', function * () {
      const params = { id_token_hint: this.idToken };
      const client = yield provider.get('Client').find('client');
      delete client.backchannelLogoutUri;

      sinon.spy(client, 'backchannelLogout');

      return agent.get('/session/end')
      .query(params)
      .expect(function () {
        expect(client.backchannelLogout.called).to.be.false;
        client.backchannelLogout.restore();
      });
    });
  });
});
