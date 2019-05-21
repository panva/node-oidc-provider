const { parse } = require('url');
const url = require('url');

const { expect } = require('chai');
const base64url = require('base64url');
const jose = require('@panva/jose');

const bootstrap = require('../test_helper');
const JWT = require('../../lib/helpers/jwt');

const { privKey } = require('./encryption.config');

const route = '/auth';

['get', 'post'].forEach((verb) => {
  describe(`[encryption] IMPLICIT id_token+token ${verb} ${route}`, () => {
    before(bootstrap(__dirname));

    before(function () {
      this.keystore = jose.JWKS.KeyStore.fromJWKS(privKey);
    });
    before(function () { return this.login(); });

    describe('encrypted authorization results', () => {
      before(function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
        });

        return this.wrap({ route, verb, auth })
          .expect(auth.validateFragment)
          .expect((response) => {
            const { query } = url.parse(response.headers.location, true);
            this.id_token = query.id_token;
            this.access_token = query.access_token;
          });
      });

      it('responds with a nested encrypted and signed id_token JWT', function () {
        expect(this.id_token).to.be.ok;
        expect(this.id_token.split('.')).to.have.lengthOf(5);

        const result = jose.JWE.decrypt(this.id_token, this.keystore);
        expect(result).to.be.ok;
        expect(result.toString().split('.')).to.have.lengthOf(3);
        expect(JWT.decode(result)).to.be.ok;
      });

      it('responds with an encrypted userinfo JWT', function (done) {
        this.agent.get('/me')
          .auth(this.access_token, { type: 'bearer' })
          .expect(200)
          .expect('content-type', /application\/jwt/)
          .expect((response) => {
            expect(response.text.split('.')).to.have.lengthOf(5);
          })
          .end((err, response) => {
            if (err) throw err;
            const result = jose.JWE.decrypt(response.text, this.keystore);
            expect(result).to.be.ok;
            expect(JSON.parse(result)).to.have.keys('sub');
            done();
          });
      });

      describe('userinfo nested signed and encrypted', () => {
        before(async function () {
          const client = await this.provider.Client.find('client');
          client.userinfoSignedResponseAlg = 'RS256';
        });

        after(async function () {
          const client = await this.provider.Client.find('client');
          client.userinfoSignedResponseAlg = undefined;
        });

        it('also handles nested encrypted and signed userinfo JWT', function (done) {
          this.agent.get('/me')
            .auth(this.access_token, { type: 'bearer' })
            .expect(200)
            .expect('content-type', /application\/jwt/)
            .expect((response) => {
              expect(response.text.split('.')).to.have.lengthOf(5);
            })
            .end((err, response) => {
              if (err) throw err;
              const result = jose.JWE.decrypt(response.text, this.keystore);
              expect(result).to.be.ok;
              expect(result.toString().split('.')).to.have.lengthOf(3);
              const decode = JWT.decode(result);
              expect(decode).to.be.ok;
              expect(decode.payload).to.have.property('exp').above(Date.now() / 1000);
              done();
            });
        });
      });
    });

    describe('authorization request object encryption', () => {
      it('works with signed by none', function () {
        return JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then(signed => JWT.encrypt(signed, i(this.provider).keystore.get({ kty: 'RSA' }), { enc: 'A128CBC-HS256', alg: 'RSA1_5' })).then(encrypted => this.wrap({
          route,
          verb,
          auth: {
            request: encrypted,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(302)
          .expect((response) => {
            const expected = parse('https://client.example.com/cb', true);
            const actual = parse(response.headers.location, true);
            ['protocol', 'host', 'pathname'].forEach((attr) => {
              expect(actual[attr]).to.equal(expected[attr]);
            });
            expect(actual.query).to.have.property('code');
          }));
      });

      it('handles enc unsupported algs', function () {
        return JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then(signed => JWT.encrypt(signed, i(this.provider).keystore.get({ kty: 'RSA' }), { enc: 'A128CBC-HS256', alg: 'RSA-OAEP' })).then(encrypted => this.wrap({
          route,
          verb,
          auth: {
            request: encrypted,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect((response) => {
            const { query } = url.parse(response.headers.location, true);
            expect(query).to.have.property('error', 'invalid_request_object');
            expect(query).to.have.property('error_description').contains('unsupported encrypted request alg');
          }));
      });

      it('handles enc unsupported encs', function () {
        return JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then(signed => JWT.encrypt(signed, i(this.provider).keystore.get({ kty: 'RSA' }), { enc: 'A192CBC-HS384', alg: 'RSA1_5' })).then(encrypted => this.wrap({
          route,
          verb,
          auth: {
            request: encrypted,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect((response) => {
            const { query } = url.parse(response.headers.location, true);
            expect(query).to.have.property('error', 'invalid_request_object');
            expect(query).to.have.property('error_description').contains('unsupported encrypted request enc');
          }));
      });
    });

    it('handles when no suitable encryption key is found', async function () {
      const client = await this.provider.Client.find('client');

      client.idTokenEncryptedResponseAlg = 'ECDH-ES';

      const auth = new this.AuthorizationRequest({
        response_type: 'id_token token',
        scope: 'openid',
      });

      return this.wrap({ route, verb, auth })
        .expect(() => {
          client.idTokenEncryptedResponseAlg = 'RSA1_5';
        })
        .expect(auth.validateFragment)
        .expect((response) => {
          const { query } = url.parse(response.headers.location, true);
          expect(query).to.have.property('error', 'invalid_client_metadata');
          expect(query).to.have.property('error_description', 'no suitable encryption key found (ECDH-ES)');
        });
    });

    describe('symmetric encryption', () => {
      before(function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'id_token',
          scope: 'openid',
          client_id: 'clientSymmetric',
        });

        return this.wrap({ route, verb, auth })
          .expect(auth.validateFragment)
          .expect((response) => {
            const { query } = url.parse(response.headers.location, true);
            this.id_token = query.id_token;
          });
      });

      it('accepts symmetrical encrypted request objects', async function () {
        const client = await this.provider.Client.find('clientSymmetric');
        return JWT.sign({
          client_id: 'clientSymmetric',
          response_type: 'id_token',
          nonce: 'foobar',
          redirect_uri: 'https://client.example.com/cb',
        }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then(signed => JWT.encrypt(signed, client.keystore.get({ alg: 'A128KW' }), { enc: 'A128CBC-HS256', alg: 'A128KW' })).then(encrypted => this.wrap({
          route,
          verb,
          auth: {
            request: encrypted,
            scope: 'openid',
            client_id: 'clientSymmetric',
            response_type: 'id_token',
          },
        })
          .expect(302)
          .expect((response) => {
            const expected = parse('https://client.example.com/cb', true);
            const actual = parse(response.headers.location.replace('#', '?'), true);
            ['protocol', 'host', 'pathname'].forEach((attr) => {
              expect(actual[attr]).to.equal(expected[attr]);
            });
            expect(actual.query).to.have.property('id_token');
          }));
      });

      it('symmetric encryption makes client secret mandatory', function () {
        expect(this.provider.Client.needsSecret({
          token_endpoint_auth_method: 'none',
          id_token_encrypted_response_alg: 'A128KW',
        })).to.be.true;
      });

      it('responds encrypted with i.e. PBES2 password encrypted key', function () {
        expect(this.id_token).to.be.ok;
        expect(this.id_token.split('.')).to.have.lengthOf(5);
        expect(JSON.parse(base64url.decode(this.id_token.split('.')[0]))).to.have.property('alg', 'PBES2-HS384+A192KW');
      });
    });
  });
});
