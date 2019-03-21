const url = require('url');

const { expect } = require('chai');

const bootstrap = require('../test_helper');
const JWT = require('../../lib/helpers/jwt');

const route = '/auth';
const verb = 'get';

describe('audiences helper', () => {
  before(bootstrap(__dirname, { config: 'audiences' }));
  before(function () { return this.login(); });
  bootstrap.skipConsent();
  before(async function () {
    const auth = new this.AuthorizationRequest({
      response_type: 'code id_token token',
      scope: 'openid offline_access',
      prompt: 'consent',
    });

    await this.wrap({ route, verb, auth })
      .expect(302)
      .expect(auth.validateFragment)
      .expect((response) => {
        const {
          query: {
            id_token,
            code,
            access_token,
          },
        } = url.parse(response.headers.location, true);

        this.access_token = access_token;
        this.code = code;
        this.id_token = id_token;
      });
  });

  it('does not push audiences to id tokens issued by the authorization endpoint', function () {
    const { payload } = JWT.decode(this.id_token);
    expect(payload).not.to.have.property('azp');
    expect(payload).to.have.property('aud', 'client');
  });

  it('does not push audiences to signed userinfo responses', function () {
    return this.agent.get('/me')
      .auth(this.access_token, { type: 'bearer' })
      .expect(200)
      .expect('content-type', 'application/jwt; charset=utf-8')
      .expect((response) => {
        const { payload } = JWT.decode(response.text);
        expect(payload).not.to.have.property('azp');
        expect(payload).to.have.property('aud', 'client');
      });
  });

  it('it does not push audiences to id tokens issued by the token endpoint', async function () {
    await this.agent.post('/token')
      .auth('client', 'secret')
      .type('form')
      .send({
        code: this.code,
        grant_type: 'authorization_code',
        redirect_uri: 'https://client.example.com/cb',
      })
      .expect(200)
      .expect((response) => {
        expect(response.body).to.have.property('refresh_token');
        this.refresh_token = response.body.refresh_token;
        expect(response.body).to.have.property('id_token');
        const { payload } = JWT.decode(response.body.id_token);
        expect(payload).not.to.have.property('azp');
        expect(payload).to.have.property('aud', 'client');
      });

    await this.agent.post('/token')
      .auth('client', 'secret')
      .type('form')
      .send({
        refresh_token: this.refresh_token,
        grant_type: 'refresh_token',
      })
      .expect(200)
      .expect((response) => {
        expect(response.body).to.have.property('id_token');
        const { payload } = JWT.decode(response.body.id_token);
        expect(payload).not.to.have.property('azp');
        expect(payload).to.have.property('aud', 'client');
      });
  });
});
