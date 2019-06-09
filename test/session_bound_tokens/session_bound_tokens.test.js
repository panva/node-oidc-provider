const url = require('url');

const { expect } = require('chai');

const bootstrap = require('../test_helper');

function assignAuthorizationResponseValues({ headers: { location } }) {
  const { query: { access_token, code } } = url.parse(location, true);

  this.access_token = access_token;
  this.code = code;
}

function assignTokenResponseValues({ body }) {
  this.access_token = body.access_token;
  this.refresh_token = body.refresh_token;
}

describe('session bound tokens behaviours', () => {
  before(bootstrap(__dirname));
  bootstrap.skipConsent();

  beforeEach(function () { return this.login(); });
  after(function () { return this.logout(); });

  describe('authorization_code flow', () => {
    it('"code" issues tokens bound to session', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      await this.agent.get('/auth')
        .query(auth)
        .expect(302)
        .expect(auth.validatePresence(['code', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(assignAuthorizationResponseValues.bind(this));

      const code = await this.provider.AuthorizationCode.find(this.code);
      expect(code).to.have.property('expiresWithSession', true);

      await this.agent.post('/token')
        .send({
          client_id: 'client',
          code: this.code,
          grant_type: 'authorization_code',
        })
        .type('form')
        .expect(200)
        .expect(assignTokenResponseValues.bind(this));

      const token = await this.provider.AccessToken.find(this.access_token);
      expect(token).to.have.property('expiresWithSession', true);

      await this.agent.get('/me')
        .auth(this.access_token, { type: 'bearer' })
        .expect(200);

      await this.TestAdapter.for('Session').destroy(this.getSessionId());

      await this.agent.get('/me')
        .auth(this.access_token, { type: 'bearer' })
        .expect(401);
    });

    it('"code" with "online" refresh token', async function () {
      const auth = new this.AuthorizationRequest({
        client_id: 'client-refresh',
        response_type: 'code',
        scope: 'openid',
      });

      await this.agent.get('/auth')
        .query(auth)
        .expect(302)
        .expect(auth.validatePresence(['code', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(assignAuthorizationResponseValues.bind(this));

      const code = await this.provider.AuthorizationCode.find(this.code);
      expect(code).to.have.property('expiresWithSession', true);

      await this.agent.post('/token')
        .send({
          client_id: 'client-refresh',
          code: this.code,
          grant_type: 'authorization_code',
        })
        .type('form')
        .expect(200)
        .expect(assignTokenResponseValues.bind(this));

      let token = await this.provider.AccessToken.find(this.access_token);
      expect(token).to.have.property('expiresWithSession', true);
      let refresh = await this.provider.RefreshToken.find(this.refresh_token);
      expect(refresh).to.have.property('expiresWithSession', true);

      await this.agent.get('/me')
        .auth(this.access_token, { type: 'bearer' })
        .expect(200);

      await this.agent.post('/token')
        .send({
          client_id: 'client-refresh',
          refresh_token: this.refresh_token,
          grant_type: 'refresh_token',
        })
        .type('form')
        .expect(200)
        .expect(assignTokenResponseValues.bind(this));

      token = await this.provider.AccessToken.find(this.access_token);
      expect(token).to.have.property('expiresWithSession', true);
      refresh = await this.provider.RefreshToken.find(this.refresh_token);
      expect(refresh).to.have.property('expiresWithSession', true);

      await this.TestAdapter.for('Session').destroy(this.getSessionId());

      await this.agent.get('/me')
        .auth(this.access_token, { type: 'bearer' })
        .expect(401);

      await this.agent.post('/token')
        .send({
          client_id: 'client-refresh',
          refresh_token: this.refresh_token,
          grant_type: 'refresh_token',
        })
        .type('form')
        .expect(400)
        .expect(assignTokenResponseValues.bind(this));
    });

    it('"code" with offline_access refresh token isnt affected', async function () {
      const auth = new this.AuthorizationRequest({
        client_id: 'client-offline',
        response_type: 'code',
        scope: 'openid offline_access',
        prompt: 'consent',
      });

      await this.agent.get('/auth')
        .query(auth)
        .expect(302)
        .expect(auth.validatePresence(['code', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(assignAuthorizationResponseValues.bind(this));

      const code = await this.provider.AuthorizationCode.find(this.code);
      expect(code).not.to.have.property('expiresWithSession');

      await this.agent.post('/token')
        .send({
          client_id: 'client-offline',
          code: this.code,
          grant_type: 'authorization_code',
        })
        .type('form')
        .expect(200)
        .expect(assignTokenResponseValues.bind(this));

      let token = await this.provider.AccessToken.find(this.access_token);
      expect(token).not.to.have.property('expiresWithSession');
      let refresh = await this.provider.RefreshToken.find(this.refresh_token);
      expect(refresh).not.to.have.property('expiresWithSession');

      await this.agent.get('/me')
        .auth(this.access_token, { type: 'bearer' })
        .expect(200);

      await this.agent.post('/token')
        .send({
          client_id: 'client-offline',
          refresh_token: this.refresh_token,
          grant_type: 'refresh_token',
        })
        .type('form')
        .expect(200)
        .expect(assignTokenResponseValues.bind(this));

      token = await this.provider.AccessToken.find(this.access_token);
      expect(token).not.to.have.property('expiresWithSession');
      refresh = await this.provider.RefreshToken.find(this.refresh_token);
      expect(refresh).not.to.have.property('expiresWithSession');

      await this.TestAdapter.for('Session').destroy(this.getSessionId());

      await this.agent.get('/me')
        .auth(this.access_token, { type: 'bearer' })
        .expect(200);

      await this.agent.post('/token')
        .send({
          client_id: 'client-offline',
          refresh_token: this.refresh_token,
          grant_type: 'refresh_token',
        })
        .type('form')
        .expect(200)
        .expect(assignTokenResponseValues.bind(this));

      token = await this.provider.AccessToken.find(this.access_token);
      expect(token).not.to.have.property('expiresWithSession');
      refresh = await this.provider.RefreshToken.find(this.refresh_token);
      expect(refresh).not.to.have.property('expiresWithSession');
    });
  });

  describe('implicit', () => {
    it('"id_token token" issues token bound to session', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'id_token token',
        scope: 'openid',
      });

      await this.agent.get('/auth')
        .query(auth)
        .expect(302)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['id_token', 'state', 'access_token', 'expires_in', 'token_type', 'scope']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(assignAuthorizationResponseValues.bind(this));

      const token = await this.provider.AccessToken.find(this.access_token);
      expect(token).to.have.property('expiresWithSession', true);

      await this.agent.get('/me')
        .auth(this.access_token, { type: 'bearer' })
        .expect(200);

      await this.TestAdapter.for('Session').destroy(this.getSessionId());

      await this.agent.get('/me')
        .auth(this.access_token, { type: 'bearer' })
        .expect(401);
    });
  });
});
