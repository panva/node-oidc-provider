const { parse: parseUrl } = require('url');

const { expect } = require('chai');
const timekeeper = require('timekeeper');

const bootstrap = require('../test_helper');

const route = '/token';

describe('grant_type=refresh_token', () => {
  before(bootstrap(__dirname));

  afterEach(() => timekeeper.reset());
  afterEach(function () {
    this.provider.removeAllListeners();
  });

  beforeEach(function () { return this.login({ scope: 'openid email offline_access' }); });
  afterEach(function () { return this.logout(); });
  bootstrap.skipConsent();

  afterEach(function () {
    this.provider.removeAllListeners();
  });

  it('ignores the offline_access scope', function (done) {
    this.agent.get('/auth')
      .query({
        client_id: 'client',
        scope: 'openid email offline_access',
        prompt: 'login',
        response_type: 'code',
        redirect_uri: 'https://client.example.com/cb',
        nonce: 'foobarnonce',
      })
      .expect(303)
      .end((err, authResponse) => {
        if (err) {
          return done(err);
        }

        const { query: { code } } = parseUrl(authResponse.headers.location, true);

        return this.agent.post(route)
          .auth('client', 'secret')
          .type('form')
          .send({
            code,
            grant_type: 'authorization_code',
            redirect_uri: 'https://client.example.com/cb',
          })
          .expect(200)
          .expect((response) => {
            expect(response.body).to.not.have.property('refresh_token');
          })
          .end(done);
      });
  });

  describe('override ignoreOfflineAccessScope to never consider the prompt', () => {
    bootstrap.dontIgnoreOfflineAccessScope();

    it('does not ignore the offline_access scope when the prompt is login', function (done) {
      this.agent.get('/auth')
        .query({
          client_id: 'client',
          scope: 'openid email offline_access',
          prompt: 'login',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          nonce: 'foobarnonce',
        })
        .expect(303)
        .end((err, authResponse) => {
          if (err) {
            return done(err);
          }

          const { query: { code } } = parseUrl(authResponse.headers.location, true);

          return this.agent.post(route)
            .auth('client', 'secret')
            .type('form')
            .send({
              code,
              grant_type: 'authorization_code',
              redirect_uri: 'https://client.example.com/cb',
            })
            .expect(200)
            .expect((response) => {
              expect(response.body).to.have.property('refresh_token');
              const jti = this.getTokenJti(response.body.refresh_token);
              this.refreshToken = this.TestAdapter.for('RefreshToken').syncFind(jti);
              expect(this.refreshToken).to.have.property('gty', 'authorization_code');
              this.rt = response.body.refresh_token;
            })
            .end(done);
        });
    });
  });
});
