import { describe, before, it, after } from 'node:test';
import assert from 'node:assert/strict';
import * as url from 'node:url';

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
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  before(() => fixture.login(), { timeout: 3000 });

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
      it(`symmetric ${attr} makes client secret mandatory (${alg})`, { timeout: 3000 }, () => {
        assert.equal(fixture.provider.Client.needsSecret({
          token_endpoint_auth_method: 'none',
          [attr]: alg,
        }), true);
      });
    });
  });

  ['get', 'post'].forEach((verb) => {
    describe(`[encryption] IMPLICIT id_token+token ${verb} ${route}`, () => {
      const fixture1 = Object.create(fixture);

      describe('expired secret id token response', () => {
        const fixture2 = Object.create(fixture1);

        it('errors out with a specific message', { timeout: 3000 }, () => {
          const auth = new fixture2.AuthorizationRequest({
            response_type: 'id_token',
            client_id: 'clientSymmetric-expired',
            scope: 'openid',
          });

          return fixture2.wrap({ route, verb, auth }).expect(303)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['error', 'error_description', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(auth.validateError('invalid_client'))
            .expect(auth.validateErrorDescription('client secret is expired - cannot issue an encrypted ID Token (A128KW)'));
        });
      });

      describe('encrypted authorization results', () => {
        const fixture3 = Object.create(fixture1);

        before(() => {
          const auth = new fixture3.AuthorizationRequest({
            response_type: 'id_token token',
            scope: 'openid',
          });

          return fixture3.wrap({ route, verb, auth })
            .expect(auth.validateFragment)
            .expect((response) => {
              const { query } = url.parse(response.headers.location, true);
              fixture3.id_token = query.id_token;
              fixture3.access_token = query.access_token;
            });
        }, { timeout: 3000 });

        it('responds with a nested encrypted and signed id_token JWT', { timeout: 3000 }, async () => {
          assert.ok(fixture3.id_token);
          assert.equal(fixture3.id_token.split('.').length, 5);

          const { plaintext } = await compactDecrypt(fixture3.id_token, keypair.privateKey);
          assert.ok(plaintext);
          assert.ok(decodeJwt(decoder.decode(plaintext)));
        });

        it('duplicates iss and aud as JWE Header Parameters in an encrypted ID Token', { timeout: 3000 }, () => {
          const header = decodeProtectedHeader(fixture3.id_token);
          ((actual) => { assert.ok('iss' in Object(actual)); assert.deepEqual(actual.iss, fixture3.provider.issuer); })(header);
          ((actual) => { assert.ok('aud' in Object(actual)); assert.deepEqual(actual.aud, 'client'); })(header);
        });

        it('handles nested encrypted and signed userinfo JWT', { timeout: 3000 }, (_t, done) => {
          fixture3.agent.get('/me')
            .auth(fixture3.access_token, { type: 'bearer' })
            .expect(200)
            .expect('content-type', /application\/jwt/)
            .expect((response) => {
              assert.equal(response.text.split('.').length, 5);
            })
            .end(async (err, response) => {
              if (err) throw err;

              const header = decodeProtectedHeader(response.text);
              ((actual) => { assert.ok('iss' in Object(actual)); assert.deepEqual(actual.iss, fixture3.provider.issuer); })(header);
              ((actual) => { assert.ok('aud' in Object(actual)); assert.deepEqual(actual.aud, 'client'); })(header);

              const { plaintext } = await compactDecrypt(response.text, keypair.privateKey);
              assert.ok(plaintext);
              const payload = decodeJwt(decoder.decode(plaintext));
              assert.ok(payload);
              ((actual) => { assert.ok('exp' in Object(actual)); ((value) => { assert.equal(typeof value, 'number'); assert.ok(value > Date.now() / 1000); })(actual.exp); })(payload);
              done();
            });
        });

        describe('userinfo signed - expired client secret', () => {
          const fixture4 = Object.create(fixture3);

          before(async () => {
            const client = await fixture4.provider.Client.find('client');
            client.userinfoSignedResponseAlg = 'HS256';
            client.clientSecretExpiresAt = 1;
          }, { timeout: 3000 });

          after(async () => {
            const client = await fixture4.provider.Client.find('client');
            client.userinfoSignedResponseAlg = 'RS256';
            client.clientSecretExpiresAt = 0;
          }, { timeout: 3000 });

          it('errors with a specific message', { timeout: 3000 }, () => fixture4.agent.get('/me')
              .auth(fixture4.access_token, { type: 'bearer' })
              .expect(400)
              .expect({
                error: 'invalid_client',
                error_description: 'client secret is expired - cannot respond with HS256 JWT UserInfo response',
              }));
        });

        describe('userinfo symmetric encrypted - expired client secret', () => {
          const fixture5 = Object.create(fixture3);

          before(async () => {
            const client = await fixture5.provider.Client.find('client');
            client.clientSecretExpiresAt = 1;
            client.userinfoEncryptedResponseAlg = 'dir';
          }, { timeout: 3000 });

          after(async () => {
            const client = await fixture5.provider.Client.find('client');
            client.clientSecretExpiresAt = 0;
            client.userinfoEncryptedResponseAlg = 'RSA-OAEP';
          }, { timeout: 3000 });

          it('errors with a specific message', { timeout: 3000 }, () => fixture5.agent.get('/me')
              .auth(fixture5.access_token, { type: 'bearer' })
              .expect(400)
              .expect({
                error: 'invalid_client',
                error_description: 'client secret is expired - cannot respond with dir encrypted JWT UserInfo response',
              }));
        });
      });

      describe('Request Object encryption', () => {
        const fixture6 = Object.create(fixture1);

        it('handles enc unsupported algs', { timeout: 3000 }, async () => {
          const signed = await JWT.sign({
            client_id: 'client',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
          }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: fixture6.provider.issuer });

          let [key] = i(fixture6.provider).keystore.selectForEncrypt({ kty: 'RSA', alg: 'RSA-OAEP-512' });
          key = i(fixture6.provider).keystore.getKeyObject(key, true);

          const encrypted = await new CompactEncrypt(encoder.encode(signed))
            .setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'RSA-OAEP-512' })
            .encrypt(key);

          return fixture6.wrap({
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
              ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request_object'); })(query);
              ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'could not decrypt request object'); })(query);
            });
        });

        it('handles enc unsupported encs', { timeout: 3000 }, async () => {
          const signed = await JWT.sign({
            client_id: 'client',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
          }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: fixture6.provider.issuer });

          let [key] = i(fixture6.provider).keystore.selectForEncrypt({ kty: 'RSA', alg: 'RSA-OAEP-512' });
          key = i(fixture6.provider).keystore.getKeyObject(key, true);

          const encrypted = await new CompactEncrypt(encoder.encode(signed))
            .setProtectedHeader({ enc: 'A192CBC-HS384', alg: 'RSA-OAEP-512' })
            .encrypt(key);

          return fixture6.wrap({
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
              ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request_object'); })(query);
              ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'could not decrypt request object'); })(query);
            });
        });
      });

      describe('Pushed Request Object encryption', () => {
        const fixture7 = Object.create(fixture1);

        it('works signed', { timeout: 3000 }, async () => {
          const client = await fixture7.provider.Client.find('client');
          const [hsSecret] = client.symmetricKeyStore.selectForSign({ alg: 'HS256' });
          const signed = await JWT.sign({
            client_id: 'client',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
            scope: 'openid',
          }, client.symmetricKeyStore.getKeyObject(hsSecret), 'HS256', { issuer: 'client', audience: fixture7.provider.issuer });

          let [key] = i(fixture7.provider).keystore.selectForEncrypt({ kty: 'RSA', alg: 'RSA-OAEP' });
          key = i(fixture7.provider).keystore.getKeyObject(key, true);

          const encrypted = await new CompactEncrypt(encoder.encode(signed))
            .setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'RSA-OAEP' })
            .encrypt(key);

          const { body } = await fixture7.agent.post('/request')
            .auth('client', 'secret')
            .type('form')
            .send({ request: encrypted });

          return fixture7.wrap({
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
                assert.equal(actual[attr], expected[attr]);
              });
              assert.ok('code' in Object(actual.query));
            });
        });

        it('works with signed by other than none when an alg is required', { timeout: 3000 }, async () => {
          const client = await fixture7.provider.Client.find('clientRequestObjectSigningAlg');
          const [hsSecret] = client.symmetricKeyStore.selectForSign({ alg: 'HS256' });
          const signed = await JWT.sign({
            client_id: 'clientRequestObjectSigningAlg',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
            scope: 'openid',
          }, client.symmetricKeyStore.getKeyObject(hsSecret), 'HS256', { issuer: 'clientRequestObjectSigningAlg', audience: fixture7.provider.issuer });

          let [key] = i(fixture7.provider).keystore.selectForEncrypt({ kty: 'RSA', alg: 'RSA-OAEP' });
          key = i(fixture7.provider).keystore.getKeyObject(key, true);

          const encrypted = await new CompactEncrypt(encoder.encode(signed))
            .setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'RSA-OAEP' })
            .encrypt(key);

          const { body } = await fixture7.agent.post('/request')
            .auth('clientRequestObjectSigningAlg', 'secret')
            .type('form')
            .send({ request: encrypted });

          return fixture7.wrap({
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
                assert.equal(actual[attr], expected[attr]);
              });
              assert.ok('code' in Object(actual.query));
            });
        });
      });

      it('handles when no suitable encryption key is found', { timeout: 3000 }, async () => {
        const client = await fixture1.provider.Client.find('client');

        client.idTokenEncryptedResponseAlg = 'ECDH-ES';

        const auth = new fixture1.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
        });

        return fixture1.wrap({ route, verb, auth })
          .expect(() => {
            client.idTokenEncryptedResponseAlg = 'RSA-OAEP';
          })
          .expect(auth.validateFragment)
          .expect((response) => {
            const { query } = url.parse(response.headers.location, true);
            ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_client_metadata'); })(query);
            ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'no suitable encryption key found (ECDH-ES)'); })(query);
          });
      });

      describe('symmetric encryption', () => {
        const fixture8 = Object.create(fixture1);

        before(() => {
          const auth = new fixture8.AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            client_id: 'clientSymmetric',
          });

          return fixture8.wrap({ route, verb, auth })
            .expect(auth.validateFragment)
            .expect((response) => {
              const { query } = url.parse(response.headers.location, true);
              fixture8.id_token = query.id_token;
            });
        }, { timeout: 3000 });

        it('accepts symmetric encrypted Request Objects', { timeout: 3000 }, async () => {
          const client = await fixture8.provider.Client.find('clientSymmetric');
          const signed = await JWT.sign({
            client_id: 'clientSymmetric',
            scope: 'openid',
            response_type: 'id_token',
            nonce: 'foobar',
            redirect_uri: 'https://client.example.com/cb',
          }, Buffer.from('secret'), 'HS256', { issuer: 'clientSymmetric', audience: fixture8.provider.issuer });

          let [key] = client.symmetricKeyStore.selectForEncrypt({ alg: 'A128KW' });
          key = client.symmetricKeyStore.getKeyObject(key);

          const encrypted = await new CompactEncrypt(encoder.encode(signed))
            .setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'A128KW' })
            .encrypt(key);

          return fixture8.wrap({
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
                assert.equal(actual[attr], expected[attr]);
              });
              assert.ok('id_token' in Object(actual.query));
            });
        });

        it('rejects symmetric encrypted request objects when secret is expired', { timeout: 3000 }, async () => {
          const client = await fixture8.provider.Client.find('clientSymmetric-expired');
          const signed = await JWT.sign({
            client_id: 'clientSymmetric-expired',
            response_type: 'id_token',
            nonce: 'foobar',
          }, Buffer.from('secret'), 'HS256', { issuer: 'clientSymmetric-expired', audience: fixture8.provider.issuer });

          let [key] = client.symmetricKeyStore.selectForEncrypt({ alg: 'A128KW' });
          key = client.symmetricKeyStore.getKeyObject(key);

          const encrypted = await new CompactEncrypt(encoder.encode(signed))
            .setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'A128KW' })
            .encrypt(key);

          return fixture8.wrap({
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
              ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request_object'); })(query);
              ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'could not decrypt the Request Object - the client secret used for its encryption is expired'); })(query);
            });
        });

        it('responds encrypted', { timeout: 3000 }, () => {
          assert.ok(fixture8.id_token);
          assert.equal(fixture8.id_token.split('.').length, 5);
          const header = decodeProtectedHeader(fixture8.id_token);
          ((actual) => { assert.ok('alg' in Object(actual)); assert.equal(actual.alg, 'A128KW'); })(header);
          ((actual) => { assert.ok('iss' in Object(actual)); assert.deepEqual(actual.iss, fixture8.provider.issuer); })(header);
          ((actual) => { assert.ok('aud' in Object(actual)); assert.deepEqual(actual.aud, 'clientSymmetric'); })(header);
        });
      });

      describe('direct key agreement symmetric encryption', () => {
        const fixture9 = Object.create(fixture1);

        before(() => {
          const auth = new fixture9.AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            client_id: 'clientSymmetric-dir',
          });

          return fixture9.wrap({ route, verb, auth })
            .expect(auth.validateFragment)
            .expect((response) => {
              const { query } = url.parse(response.headers.location, true);
              fixture9.id_token = query.id_token;
            });
        }, { timeout: 3000 });

        it('accepts symmetric (dir) encrypted Request Objects', { timeout: 3000 }, async () => {
          const client = await fixture9.provider.Client.find('clientSymmetric');
          const signed = await JWT.sign({
            client_id: 'clientSymmetric-dir',
            scope: 'openid',
            response_type: 'id_token',
            nonce: 'foobar',
            redirect_uri: 'https://client.example.com/cb',
          }, Buffer.from('secret'), 'HS256', { issuer: 'clientSymmetric-dir', audience: fixture9.provider.issuer });

          let [key] = client.symmetricKeyStore.selectForEncrypt({ alg: 'A128CBC-HS256' });
          key = client.symmetricKeyStore.getKeyObject(key);

          const encrypted = await new CompactEncrypt(encoder.encode(signed))
            .setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'dir' })
            .encrypt(key);

          return fixture9.wrap({
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
                assert.equal(actual[attr], expected[attr]);
              });
              assert.ok('id_token' in Object(actual.query));
            });
        });

        it('rejects symmetric (dir) encrypted request objects when secret is expired', { timeout: 3000 }, async () => {
          const client = await fixture9.provider.Client.find('clientSymmetric');
          const signed = await JWT.sign({
            client_id: 'clientSymmetric-expired',
            response_type: 'id_token',
            nonce: 'foobar',
          }, Buffer.from('secret'), 'HS256', { issuer: 'clientSymmetric-expired', audience: fixture9.provider.issuer });

          let [key] = client.symmetricKeyStore.selectForEncrypt({ alg: 'A128CBC-HS256' });
          key = client.symmetricKeyStore.getKeyObject(key);

          const encrypted = await new CompactEncrypt(encoder.encode(signed))
            .setProtectedHeader({ enc: 'A128CBC-HS256', alg: 'dir' })
            .encrypt(key);

          return fixture9.wrap({
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
              ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request_object'); })(query);
              ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'could not decrypt the Request Object - the client secret used for its encryption is expired'); })(query);
            });
        });

        it('responds encrypted', { timeout: 3000 }, () => {
          assert.ok(fixture9.id_token);
          assert.equal(fixture9.id_token.split('.').length, 5);
          const header = decodeProtectedHeader(fixture9.id_token);
          ((actual) => { assert.ok('alg' in Object(actual)); assert.equal(actual.alg, 'dir'); })(header);
          ((actual) => { assert.ok('enc' in Object(actual)); assert.equal(actual.enc, 'A128CBC-HS256'); })(header);
          ((actual) => { assert.ok('iss' in Object(actual)); assert.deepEqual(actual.iss, fixture9.provider.issuer); })(header);
          ((actual) => { assert.ok('aud' in Object(actual)); assert.deepEqual(actual.aud, 'clientSymmetric-dir'); })(header);
        });
      });
    });
  });
});
