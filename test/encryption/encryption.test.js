const url = require('url');

const { expect } = require('chai');
const base64url = require('base64url');
const sinon = require('sinon');
const jose = require('jose');

const bootstrap = require('../test_helper');
const JWT = require('../../lib/helpers/jwt');

const { privKey } = require('./encryption.config');

const route = '/auth';

describe('encryption', () => {
  before(bootstrap(__dirname));

  before(function () {
    this.keystore = jose.JWKS.asKeyStore(privKey);
  });
  before(function () { return this.login(); });

  [
    // symmetric kw
    'A128GCMKW', 'A192GCMKW', 'A256GCMKW', 'A128KW', 'A192KW', 'A256KW',
    'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
    // no kw
    'dir',
  ].forEach((alg) => {
    [
      'authorization_encrypted_response_alg',
      'id_token_encrypted_response_alg',
      'introspection_encrypted_response_alg',
      'request_object_encryption_alg',
      'userinfo_encrypted_response_alg',
    ].forEach((attr) => {
      it(`symmetric ${attr} makes client secret mandatory (${alg})`, function () {
        expect(this.provider.Client.needsSecret({
          token_endpoint_auth_method: 'none',
          [attr]: alg,
        })).to.be.true;
      });
    });
  });

  ['get', 'post'].forEach((verb) => {
    describe(`[encryption] IMPLICIT id_token+token ${verb} ${route}`, () => {
      describe('expired secret id token response', () => {
        it('errors out with a specific message', function () {
          const auth = new this.AuthorizationRequest({
            response_type: 'id_token',
            client_id: 'clientSymmetric-expired',
            scope: 'openid',
          });

          return this.wrap({ route, verb, auth }).expect(302)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['error', 'error_description', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(auth.validateError('invalid_client'))
            .expect(auth.validateErrorDescription('client secret is expired - cannot issue an encrypted ID Token (PBES2-HS384+A192KW)'));
        });
      });

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

        describe('userinfo signed - expired client secret', () => {
          before(async function () {
            const client = await this.provider.Client.find('client');
            client.userinfoSignedResponseAlg = 'HS256';
            client.clientSecretExpiresAt = 1;
          });

          after(async function () {
            const client = await this.provider.Client.find('client');
            client.userinfoSignedResponseAlg = undefined;
            client.clientSecretExpiresAt = 0;
          });

          it('errors with a specific message', function () {
            return this.agent.get('/me')
              .auth(this.access_token, { type: 'bearer' })
              .expect(400)
              .expect({
                error: 'invalid_client',
                error_description: 'client secret is expired - cannot respond with HS256 JWT UserInfo response',
              });
          });
        });

        describe('userinfo symmetric encrypted - expired client secret', () => {
          before(async function () {
            const client = await this.provider.Client.find('client');
            client.clientSecretExpiresAt = 1;
            client.userinfoEncryptedResponseAlg = 'dir';
          });

          after(async function () {
            const client = await this.provider.Client.find('client');
            client.clientSecretExpiresAt = 0;
            client.userinfoEncryptedResponseAlg = 'RSA1_5';
          });

          it('errors with a specific message', function () {
            return this.agent.get('/me')
              .auth(this.access_token, { type: 'bearer' })
              .expect(400)
              .expect({
                error: 'invalid_client',
                error_description: 'client secret is expired - cannot respond with dir encrypted JWT UserInfo response',
              });
          });
        });
      });

      describe('authorization Request Object encryption', () => {
        it('works with signed by none', function () {
          return JWT.sign({
            client_id: 'client',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
          }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then((signed) => JWT.encrypt(signed, i(this.provider).keystore.get({ kty: 'RSA' }), { enc: 'A128CBC-HS256', alg: 'RSA1_5' })).then((encrypted) => this.wrap({
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
              const expected = url.parse('https://client.example.com/cb', true);
              const actual = url.parse(response.headers.location, true);
              ['protocol', 'host', 'pathname'].forEach((attr) => {
                expect(actual[attr]).to.equal(expected[attr]);
              });
              expect(actual.query).to.have.property('code');
            }));
        });

        describe('JAR only request', () => {
          it('works without any other params if client_id is replicated in the header', function () {
            return JWT.sign({
              client_id: 'client',
              response_type: 'code',
              redirect_uri: 'https://client.example.com/cb',
              scope: 'openid',
            }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then((signed) => jose.JWE.encrypt(signed, i(this.provider).keystore.get({ kty: 'RSA' }), { enc: 'A128CBC-HS256', alg: 'RSA1_5', client_id: 'client' })).then((encrypted) => this.wrap({
              route,
              verb,
              auth: {
                request: encrypted,
              },
            })
              .expect(302)
              .expect((response) => {
                const expected = url.parse('https://client.example.com/cb', true);
                const actual = url.parse(response.headers.location, true);
                ['protocol', 'host', 'pathname'].forEach((attr) => {
                  expect(actual[attr]).to.equal(expected[attr]);
                });
                expect(actual.query).to.have.property('code');
              }));
          });

          it('works without any other params if iss is replicated in the header', function () {
            return JWT.sign({
              client_id: 'client',
              response_type: 'code',
              redirect_uri: 'https://client.example.com/cb',
              scope: 'openid',
            }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then((signed) => jose.JWE.encrypt(signed, i(this.provider).keystore.get({ kty: 'RSA' }), { enc: 'A128CBC-HS256', alg: 'RSA1_5', iss: 'client' })).then((encrypted) => this.wrap({
              route,
              verb,
              auth: {
                request: encrypted,
              },
            })
              .expect(302)
              .expect((response) => {
                const expected = url.parse('https://client.example.com/cb', true);
                const actual = url.parse(response.headers.location, true);
                ['protocol', 'host', 'pathname'].forEach((attr) => {
                  expect(actual[attr]).to.equal(expected[attr]);
                });
                expect(actual.query).to.have.property('code');
              }));
          });

          it('handles invalid JWE', function () {
            const spy = sinon.spy();
            this.provider.once('authorization.error', spy);

            return JWT.sign({
              client_id: 'client',
              response_type: 'code',
              redirect_uri: 'https://client.example.com/cb',
              scope: 'openid',
            }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then((signed) => jose.JWE.encrypt(signed, i(this.provider).keystore.get({ kty: 'RSA' }), { enc: 'A128CBC-HS256', alg: 'RSA1_5', client_id: 'client' })).then((encrypted) => this.wrap({
              route,
              verb,
              auth: {
                request: encrypted.split('.').map((part, i) => {
                  if (i === 0) {
                    return 'foo';
                  }

                  return part;
                }).join('.'),
              },
            })
              .expect(400)
              .expect(() => {
                expect(spy.calledOnce).to.be.true;
                expect(spy.args[0][1]).to.have.property('message', 'invalid_request_object');
                expect(spy.args[0][1]).to.have.property('error_description', 'Request Object is not a valid JWE');
              }));
          });
        });

        it('handles enc unsupported algs', function () {
          return JWT.sign({
            client_id: 'client',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
          }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then((signed) => JWT.encrypt(signed, i(this.provider).keystore.get({ kty: 'RSA' }), { enc: 'A128CBC-HS256', alg: 'RSA-OAEP' })).then((encrypted) => this.wrap({
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
          }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then((signed) => JWT.encrypt(signed, i(this.provider).keystore.get({ kty: 'RSA' }), { enc: 'A192CBC-HS384', alg: 'RSA1_5' })).then((encrypted) => this.wrap({
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

        it('accepts symmetric encrypted Request Objects', async function () {
          const client = await this.provider.Client.find('clientSymmetric');
          return JWT.sign({
            client_id: 'clientSymmetric',
            response_type: 'id_token',
            nonce: 'foobar',
            redirect_uri: 'https://client.example.com/cb',
          }, null, 'none', { issuer: 'clientSymmetric', audience: this.provider.issuer }).then((signed) => JWT.encrypt(signed, client.keystore.get({ alg: 'A128KW' }), { enc: 'A128CBC-HS256', alg: 'A128KW' })).then((encrypted) => this.wrap({
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
              const expected = url.parse('https://client.example.com/cb', true);
              const actual = url.parse(response.headers.location.replace('#', '?'), true);
              ['protocol', 'host', 'pathname'].forEach((attr) => {
                expect(actual[attr]).to.equal(expected[attr]);
              });
              expect(actual.query).to.have.property('id_token');
            }));
        });

        it('rejects symmetric encrypted request objects when secret is expired', async function () {
          const client = await this.provider.Client.find('clientSymmetric-expired');
          return JWT.sign({
            client_id: 'clientSymmetric-expired',
            response_type: 'id_token',
            nonce: 'foobar',
          }, null, 'none', { issuer: 'clientSymmetric-expired', audience: this.provider.issuer }).then((signed) => JWT.encrypt(signed, client.keystore.get({ alg: 'A128KW' }), { enc: 'A128CBC-HS256', alg: 'A128KW' })).then((encrypted) => this.wrap({
            route,
            verb,
            auth: {
              redirect_uri: 'https://client.example.com/cb',
              request: encrypted,
              scope: 'openid',
              client_id: 'clientSymmetric-expired',
              response_type: 'id_token',
            },
          })
            .expect(302)
            .expect((response) => {
              const { query } = url.parse(response.headers.location.replace('#', '?'), true);
              expect(query).to.have.property('error', 'invalid_request_object');
              expect(query).to.have.property('error_description', 'could not decrypt the Request Object - the client secret used for its encryption is expired');
            }));
        });

        it('responds encrypted with i.e. PBES2 password derived key id_token', function () {
          expect(this.id_token).to.be.ok;
          expect(this.id_token.split('.')).to.have.lengthOf(5);
          expect(JSON.parse(base64url.decode(this.id_token.split('.')[0]))).to.have.property('alg', 'PBES2-HS384+A192KW');
        });
      });

      describe('direct key agreement symmetric encryption', () => {
        before(function () {
          const auth = new this.AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            client_id: 'clientSymmetric-dir',
          });

          return this.wrap({ route, verb, auth })
            .expect(auth.validateFragment)
            .expect((response) => {
              const { query } = url.parse(response.headers.location, true);
              this.id_token = query.id_token;
            });
        });

        it('accepts symmetric (dir) encrypted Request Objects', async function () {
          const client = await this.provider.Client.find('clientSymmetric');
          return JWT.sign({
            client_id: 'clientSymmetric-dir',
            response_type: 'id_token',
            nonce: 'foobar',
            redirect_uri: 'https://client.example.com/cb',
          }, null, 'none', { issuer: 'clientSymmetric-dir', audience: this.provider.issuer }).then((signed) => JWT.encrypt(signed, client.keystore.get({ alg: 'A128CBC-HS256' }), { enc: 'A128CBC-HS256', alg: 'dir' })).then((encrypted) => this.wrap({
            route,
            verb,
            auth: {
              request: encrypted,
              scope: 'openid',
              client_id: 'clientSymmetric-dir',
              response_type: 'id_token',
            },
          })
            .expect(302)
            .expect((response) => {
              const expected = url.parse('https://client.example.com/cb', true);
              const actual = url.parse(response.headers.location.replace('#', '?'), true);
              ['protocol', 'host', 'pathname'].forEach((attr) => {
                expect(actual[attr]).to.equal(expected[attr]);
              });
              expect(actual.query).to.have.property('id_token');
            }));
        });

        it('rejects symmetric (dir) encrypted request objects when secret is expired', async function () {
          const client = await this.provider.Client.find('clientSymmetric');
          return JWT.sign({
            client_id: 'clientSymmetric-expired',
            response_type: 'id_token',
            nonce: 'foobar',
          }, null, 'none', { issuer: 'clientSymmetric-expired', audience: this.provider.issuer }).then((signed) => JWT.encrypt(signed, client.keystore.get({ alg: 'A128CBC-HS256' }), { enc: 'A128CBC-HS256', alg: 'dir' })).then((encrypted) => this.wrap({
            route,
            verb,
            auth: {
              redirect_uri: 'https://client.example.com/cb',
              request: encrypted,
              scope: 'openid',
              client_id: 'clientSymmetric-expired',
              response_type: 'id_token',
            },
          })
            .expect(302)
            .expect((response) => {
              const { query } = url.parse(response.headers.location.replace('#', '?'), true);
              expect(query).to.have.property('error', 'invalid_request_object');
              expect(query).to.have.property('error_description', 'could not decrypt the Request Object - the client secret used for its encryption is expired');
            }));
        });

        it('responds encrypted with i.e. PBES2 password derived key id_token', function () {
          expect(this.id_token).to.be.ok;
          expect(this.id_token.split('.')).to.have.lengthOf(5);
          const header = JSON.parse(base64url.decode(this.id_token.split('.')[0]));
          expect(header).to.have.property('alg', 'dir');
          expect(header).to.have.property('enc', 'A128CBC-HS256');
        });
      });
    });
  });
});
