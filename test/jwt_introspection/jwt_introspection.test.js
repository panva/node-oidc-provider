const { expect } = require('chai');

const bootstrap = require('../test_helper');
const JWT = require('../../lib/helpers/jwt');
const Provider = require('../../lib');

const route = '/token/introspection';

describe('jwtIntrospection features', () => {
  before(bootstrap(__dirname));

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
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        grantId: 'foo',
        clientId: 'client-signed',
        scope: 'scope',
      });

      let json;
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
          json = body;
        });

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
          expect(JWT.decode(text).payload).to.eql(json);
        });
    });

    it('non-authenticated without accept: application/jwt fails', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'accountId',
        grantId: 'foo',
        clientId: 'client-encrypted-none',
        scope: 'scope',
      });

      const token = await at.save();
      await this.agent.post(route)
        .send({
          client_id: 'client-encrypted-none',
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
          client_id: 'client-encrypted-none',
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
