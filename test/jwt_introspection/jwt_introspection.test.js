const { expect } = require('chai');
const timekeeper = require('timekeeper');

const bootstrap = require('../test_helper');
const JWT = require('../../lib/helpers/jwt');
const { Provider } = require('../../lib');

const route = '/token/introspection';

describe('jwtIntrospection features', () => {
  before(bootstrap(__dirname));

  afterEach(() => timekeeper.reset());

  describe('enriched discovery', () => {
    it('shows the url now', function () {
      return this.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('introspection_signing_alg_values_supported');
        });
    });
  });

  describe('JWT Response for OAuth Token Introspection', () => {
    it('can only be enabled with introspection', () => {
      expect(() => {
        new Provider('http://localhost', { // eslint-disable-line no-new
          features: {
            jwtIntrospection: { enabled: true },
          },
        });
      }).to.throw('jwtIntrospection is only available in conjuction with introspection');
    });

    it('returns the response as jwt', async function () {
      const now = Date.now();
      timekeeper.freeze(now);
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        grantId: 'foo',
        clientId: 'client-signed',
        scope: 'scope',
      });

      let json;
      let iat;
      const token = await at.save();
      await this.agent.post(route)
        .auth('client-signed', 'secret')
        .send({
          token,
        })
        .type('form')
        .expect(200)
        .expect('content-type', 'application/json; charset=utf-8')
        .expect(({ body }) => {
          ({ iat, ...json } = body);
        });

      timekeeper.travel(now + (10 * 1000));

      return this.agent.post(route)
        .auth('client-signed', 'secret')
        .send({
          token,
        })
        .type('form')
        .accept('application/jwt')
        .expect(200)
        .expect('content-type', 'application/jwt; charset=utf-8')
        .expect(({ text }) => {
          const { payload: { iat: jwtIat, ...payload }, header } = JWT.decode(text);
          expect(payload).to.eql(json);
          expect(jwtIat).to.eql(iat + 10);
          expect(header).to.have.property('typ', 'token-introspection+jwt');
        });
    });

    it('errors when secret is expired for HMAC alg', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        grantId: 'foo',
        clientId: 'client-HS-expired',
        scope: 'scope',
      });

      const token = await at.save();

      return this.agent.post(route)
        .send({
          client_id: 'client-HS-expired',
          token,
        })
        .type('form')
        .accept('application/jwt')
        .expect(400)
        .expect('content-type', 'application/json; charset=utf-8')
        .expect({
          error: 'invalid_client',
          error_description: 'client secret is expired - cannot respond with HS256 JWT Introspection response',
        });
    });

    it('non-authenticated without accept: application/jwt fails', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        grantId: 'foo',
        clientId: 'client-encrypted',
        scope: 'scope',
      });

      const token = await at.save();
      await this.agent.post(route)
        .send({
          client_id: 'client-encrypted',
          token,
        })
        .type('form')
        .expect(400)
        .expect('content-type', 'application/json; charset=utf-8')
        .expect({
          error: 'invalid_request',
          error_description: 'introspection must be requested with Accept: application/jwt for this client',
        });

      return this.agent.post(route)
        .send({
          client_id: 'client-encrypted',
          token,
        })
        .type('form')
        .accept('application/jwt')
        .expect(200)
        .expect('content-type', 'application/jwt; charset=utf-8')
        .expect(({ text }) => {
          const header = JWT.header(text);
          expect(header).to.have.property('alg', 'PBES2-HS256+A128KW');
          expect(header).to.have.property('enc', 'A128CBC-HS256');
        });
    });
  });
});
