import * as url from 'node:url';

import { expect } from 'chai';
import sinon from 'sinon';
import {
  compactDecrypt, CompactEncrypt, decodeJwt, decodeProtectedHeader,
} from 'jose';

import bootstrap from '../test_helper.js';
import * as JWT from '../../lib/helpers/jwt.js';

import { keypair } from './encryption.config.js';

const route = '/auth';

const decoder = new TextDecoder();
const encoder = new TextEncoder();

describe('encryption', () => {
  before(bootstrap(import.meta.url));

  before(function () { return this.login(); });

  [
    // symmetric kw
    'A128GCMKW', 'A192GCMKW', 'A256GCMKW', 'A128KW', 'A192KW', 'A256KW',
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

          return this.wrap({ route, verb, auth }).expect(303)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['error', 'error_description', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(auth.validateError('invalid_client'))
            .expect(auth.validateErrorDescription('client secret is expired - cannot issue an encrypted ID Token (A128KW)'));
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

        it('responds with a nested encrypted and signed id_token JWT', async function () {
          expect(this.id_token).to.be.ok;
          expect(this.id_token.split('.')).to.have.lengthOf(5);

          const { plaintext } = await compactDecrypt(this.id_token, keypair.privateKey);
          expect(plaintext).to.be.ok;
          expect(decodeJwt(decoder.decode(plaintext))).to.be.ok;
        });

        it('duplicates iss and aud as JWE Header Parameters in an encrypted ID Token', function () {
          const header = decodeProtectedHeader(this.id_token);
          expect(header).to.have.property('iss').eql(this.provider.issuer);
          expect(header).to.have.property('aud').eql('client');
        });

        it('handles nested encrypted and signed userinfo JWT', function (done) {
          this.agent.get('/me')
            .auth(this.access_token, { type: 'bearer' })
            .expect(200)
            .expect('content-type', /application\/jwt/)
            .expect((response) => {
              expect(response.text.split('.')).to.have.lengthOf(5);
            })
            .end(async (err, response) => {
              if (err) throw err;

              const header = decodeProtectedHeader(response.text);
              expect(header).to.have.property('iss').eql(this.provider.issuer);
              expect(header).to.have.property('aud').eql('client');

              const { plaintext } = await compactDecrypt(response.text, keypair.privateKey);
              expect(plaintext).to.be.ok;
              const payload = decodeJwt(decoder.decode(plaintext));
              expect(payload).to.be.ok;
              expect(payload).to.have.property('exp').above(Date.now() / 1000);
              done();
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
            client.userinfoSignedResponseAlg = 'RS256';
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
            client.userinfoEncryptedResponseAlg = 'RSA-OAEP';
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

      describe('Request Object encryption', () => {
        describe('JAR only request', () => {
          it('fails without any other params even if client_id is replicated in the header', async function () {
            const spy = sinon.spy();
            this.provider.once('authorization.error', spy);

            const signed = await JWT.sign({
              client_id: 'client',
              response_type: 'code',
              redirect_uri: 'https://client.example.com/cb',
              scope: 'openid',
            }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: this.provider.issuer });

            let [key] = i(this.provider).keystore.selectForEncrypt({ kty: 'RSA', alg: 'RSA-OAEP' });
            key = await i(this.provider).keystore.getKeyObject(key, 'RSA-OAEP');

            const encrypted = await new CompactEncrypt(encoder.encode(signed))
              .setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'RSA-OAEP', client_id: 'client' })
              .encrypt(key);

            return this.wrap({
              route,
              verb,
              auth: {
                request: encrypted,
              },
            })
              .expect(400)
              .expect(() => {
                expect(spy.calledOnce).to.be.true;
                expect(spy.args[0][1]).to.have.property('message', 'invalid_request');
                expect(spy.args[0][1]).to.have.property('error_description', "missing required parameter 'client_id'");
              });
          });

          it('works without any other params if iss is replicated in the header', async function () {
            const signed = await JWT.sign({
              client_id: 'client',
              response_type: 'code',
              redirect_uri: 'https://client.example.com/cb',
              scope: 'openid',
            }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: this.provider.issuer });

            let [key] = i(this.provider).keystore.selectForEncrypt({ kty: 'RSA', alg: 'RSA-OAEP' });
            key = await i(this.provider).keystore.getKeyObject(key, 'RSA-OAEP');

            const encrypted = await new CompactEncrypt(encoder.encode(signed))
              .setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'RSA-OAEP', iss: 'client' })
              .encrypt(key);

            return this.wrap({
              route,
              verb,
              auth: {
                request: encrypted,
              },
            })
              .expect(303)
              .expect((response) => {
                const expected = url.parse('https://client.example.com/cb', true);
                const actual = url.parse(response.headers.location, true);
                ['protocol', 'host', 'pathname'].forEach((attr) => {
                  expect(actual[attr]).to.equal(expected[attr]);
                });
                expect(actual.query).to.have.property('code');
              });
          });

          it('handles invalid JWE', async function () {
            const spy = sinon.spy();
            this.provider.once('authorization.error', spy);

            const signed = await JWT.sign({
              client_id: 'client',
              response_type: 'code',
              redirect_uri: 'https://client.example.com/cb',
              scope: 'openid',
            }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: this.provider.issuer });

            let [key] = i(this.provider).keystore.selectForEncrypt({ kty: 'RSA', alg: 'RSA-OAEP' });
            key = await i(this.provider).keystore.getKeyObject(key, 'RSA-OAEP');

            const encrypted = await new CompactEncrypt(encoder.encode(signed))
              .setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'RSA-OAEP', client_id: 'client' })
              .encrypt(key);

            return this.wrap({
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
              });
          });
        });

        it('handles enc unsupported algs', async function () {
          const signed = await JWT.sign({
            client_id: 'client',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
          }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: this.provider.issuer });

          let [key] = i(this.provider).keystore.selectForEncrypt({ kty: 'RSA', alg: 'RSA-OAEP-512' });
          key = await i(this.provider).keystore.getKeyObject(key, 'RSA-OAEP-512');

          const encrypted = await new CompactEncrypt(encoder.encode(signed))
            .setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'RSA-OAEP-512' })
            .encrypt(key);

          return this.wrap({
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
              expect(query).to.have.property('error_description', 'could not decrypt request object');
            });
        });

        it('handles enc unsupported encs', async function () {
          const signed = await JWT.sign({
            client_id: 'client',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
          }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: this.provider.issuer });

          let [key] = i(this.provider).keystore.selectForEncrypt({ kty: 'RSA', alg: 'RSA-OAEP-512' });
          key = await i(this.provider).keystore.getKeyObject(key, 'RSA-OAEP-512');

          const encrypted = await new CompactEncrypt(encoder.encode(signed))
            .setProtectedHeader({ enc: 'A192CBC-HS384', alg: 'RSA-OAEP-512' })
            .encrypt(key);

          return this.wrap({
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
              expect(query).to.have.property('error_description', 'could not decrypt request object');
            });
        });
      });

      describe('Pushed Request Object encryption', () => {
        it('works signed', async function () {
          const client = await this.provider.Client.find('client');
          const [hsSecret] = client.symmetricKeyStore.selectForSign({ alg: 'HS256' });
          const signed = await JWT.sign({
            client_id: 'client',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
            scope: 'openid',
          }, await client.symmetricKeyStore.getKeyObject(hsSecret, 'HS256'), 'HS256', { issuer: 'client', audience: this.provider.issuer });

          let [key] = i(this.provider).keystore.selectForEncrypt({ kty: 'RSA', alg: 'RSA-OAEP' });
          key = await i(this.provider).keystore.getKeyObject(key, 'RSA-OAEP');

          const encrypted = await new CompactEncrypt(encoder.encode(signed))
            .setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'RSA-OAEP' })
            .encrypt(key);

          const { body } = await this.agent.post('/request')
            .auth('client', 'secret')
            .type('form')
            .send({ request: encrypted });

          return this.wrap({
            route,
            verb,
            auth: {
              request_uri: body.request_uri,
              client_id: 'client',
            },
          })
            .expect(303)
            .expect((response) => {
              const expected = url.parse('https://client.example.com/cb', true);
              const actual = url.parse(response.headers.location, true);
              ['protocol', 'host', 'pathname'].forEach((attr) => {
                expect(actual[attr]).to.equal(expected[attr]);
              });
              expect(actual.query).to.have.property('code');
            });
        });

        it('works with signed by other than none when an alg is required', async function () {
          const client = await this.provider.Client.find('clientRequestObjectSigningAlg');
          const [hsSecret] = client.symmetricKeyStore.selectForSign({ alg: 'HS256' });
          const signed = await JWT.sign({
            client_id: 'clientRequestObjectSigningAlg',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
            scope: 'openid',
          }, await client.symmetricKeyStore.getKeyObject(hsSecret, 'HS256'), 'HS256', { issuer: 'clientRequestObjectSigningAlg', audience: this.provider.issuer });

          let [key] = i(this.provider).keystore.selectForEncrypt({ kty: 'RSA', alg: 'RSA-OAEP' });
          key = await i(this.provider).keystore.getKeyObject(key, 'RSA-OAEP');

          const encrypted = await new CompactEncrypt(encoder.encode(signed))
            .setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'RSA-OAEP' })
            .encrypt(key);

          const { body } = await this.agent.post('/request')
            .auth('clientRequestObjectSigningAlg', 'secret')
            .type('form')
            .send({ request: encrypted });

          return this.wrap({
            route,
            verb,
            auth: {
              request_uri: body.request_uri,
              client_id: 'clientRequestObjectSigningAlg',
            },
          })
            .expect(303)
            .expect((response) => {
              const expected = url.parse('https://client.example.com/cb', true);
              const actual = url.parse(response.headers.location, true);
              ['protocol', 'host', 'pathname'].forEach((attr) => {
                expect(actual[attr]).to.equal(expected[attr]);
              });
              expect(actual.query).to.have.property('code');
            });
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
            client.idTokenEncryptedResponseAlg = 'RSA-OAEP';
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
          const signed = await JWT.sign({
            client_id: 'clientSymmetric',
            scope: 'openid',
            response_type: 'id_token',
            nonce: 'foobar',
            redirect_uri: 'https://client.example.com/cb',
          }, Buffer.from('secret'), 'HS256', { issuer: 'clientSymmetric', audience: this.provider.issuer });

          let [key] = client.symmetricKeyStore.selectForEncrypt({ alg: 'A128KW' });
          key = await client.symmetricKeyStore.getKeyObject(key, 'A128KW');

          const encrypted = await new CompactEncrypt(encoder.encode(signed))
            .setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'A128KW' })
            .encrypt(key);

          return this.wrap({
            route,
            verb,
            auth: {
              request: encrypted,
              scope: 'openid',
              client_id: 'clientSymmetric',
              response_type: 'id_token',
            },
          })
            .expect(303)
            .expect((response) => {
              const expected = url.parse('https://client.example.com/cb', true);
              const actual = url.parse(response.headers.location.replace('#', '?'), true);
              ['protocol', 'host', 'pathname'].forEach((attr) => {
                expect(actual[attr]).to.equal(expected[attr]);
              });
              expect(actual.query).to.have.property('id_token');
            });
        });

        it('rejects symmetric encrypted request objects when secret is expired', async function () {
          const client = await this.provider.Client.find('clientSymmetric-expired');
          const signed = await JWT.sign({
            client_id: 'clientSymmetric-expired',
            response_type: 'id_token',
            nonce: 'foobar',
          }, Buffer.from('secret'), 'HS256', { issuer: 'clientSymmetric-expired', audience: this.provider.issuer });

          let [key] = client.symmetricKeyStore.selectForEncrypt({ alg: 'A128KW' });
          key = await client.symmetricKeyStore.getKeyObject(key, 'A128KW');

          const encrypted = await new CompactEncrypt(encoder.encode(signed))
            .setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'A128KW' })
            .encrypt(key);

          return this.wrap({
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
            .expect(303)
            .expect((response) => {
              const { query } = url.parse(response.headers.location.replace('#', '?'), true);
              expect(query).to.have.property('error', 'invalid_request_object');
              expect(query).to.have.property('error_description', 'could not decrypt the Request Object - the client secret used for its encryption is expired');
            });
        });

        it('responds encrypted', function () {
          expect(this.id_token).to.be.ok;
          expect(this.id_token.split('.')).to.have.lengthOf(5);
          const header = decodeProtectedHeader(this.id_token);
          expect(header).to.have.property('alg', 'A128KW');
          expect(header).to.have.property('iss').eql(this.provider.issuer);
          expect(header).to.have.property('aud').eql('clientSymmetric');
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
          const signed = await JWT.sign({
            client_id: 'clientSymmetric-dir',
            scope: 'openid',
            response_type: 'id_token',
            nonce: 'foobar',
            redirect_uri: 'https://client.example.com/cb',
          }, Buffer.from('secret'), 'HS256', { issuer: 'clientSymmetric-dir', audience: this.provider.issuer });

          let [key] = client.symmetricKeyStore.selectForEncrypt({ alg: 'A128CBC-HS256' });
          key = await client.symmetricKeyStore.getKeyObject(key, 'A128CBC-HS256');

          const encrypted = await new CompactEncrypt(encoder.encode(signed))
            .setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'dir' })
            .encrypt(key);

          return this.wrap({
            route,
            verb,
            auth: {
              request: encrypted,
              scope: 'openid',
              client_id: 'clientSymmetric-dir',
              response_type: 'id_token',
            },
          })
            .expect(303)
            .expect((response) => {
              const expected = url.parse('https://client.example.com/cb', true);
              const actual = url.parse(response.headers.location.replace('#', '?'), true);
              ['protocol', 'host', 'pathname'].forEach((attr) => {
                expect(actual[attr]).to.equal(expected[attr]);
              });
              expect(actual.query).to.have.property('id_token');
            });
        });

        it('rejects symmetric (dir) encrypted request objects when secret is expired', async function () {
          const client = await this.provider.Client.find('clientSymmetric');
          const signed = await JWT.sign({
            client_id: 'clientSymmetric-expired',
            response_type: 'id_token',
            nonce: 'foobar',
          }, Buffer.from('secret'), 'HS256', { issuer: 'clientSymmetric-expired', audience: this.provider.issuer });

          let [key] = client.symmetricKeyStore.selectForEncrypt({ alg: 'A128CBC-HS256' });
          key = await client.symmetricKeyStore.getKeyObject(key, 'A128CBC-HS256');

          const encrypted = await new CompactEncrypt(encoder.encode(signed))
            .setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'dir' })
            .encrypt(key);

          return this.wrap({
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
            .expect(303)
            .expect((response) => {
              const { query } = url.parse(response.headers.location.replace('#', '?'), true);
              expect(query).to.have.property('error', 'invalid_request_object');
              expect(query).to.have.property('error_description', 'could not decrypt the Request Object - the client secret used for its encryption is expired');
            });
        });

        it('responds encrypted', function () {
          expect(this.id_token).to.be.ok;
          expect(this.id_token.split('.')).to.have.lengthOf(5);
          const header = decodeProtectedHeader(this.id_token);
          expect(header).to.have.property('alg', 'dir');
          expect(header).to.have.property('enc', 'A128CBC-HS256');
          expect(header).to.have.property('iss').eql(this.provider.issuer);
          expect(header).to.have.property('aud').eql('clientSymmetric-dir');
        });
      });
    });
  });
});
