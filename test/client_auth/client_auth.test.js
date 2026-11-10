import { describe, before, afterEach, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { createPrivateKey, X509Certificate, generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { request } from 'node:http';

import { calculateJwkThumbprint, importJWK, SignJWT } from 'jose';
import sinon from 'sinon';
import cloneDeep from 'lodash/cloneDeep.js';

import nanoid from '../../lib/helpers/nanoid.js';
import { createMemoryAdapter } from '../../lib/adapters/memory_adapter.js';
import Provider from '../../lib/index.js';
import bootstrap, { assertNoPendingInterceptors, mock } from '../test_helper.js';
import clientKey from '../client.sig.key.js';
import * as JWT from '../../lib/helpers/jwt.js';
import { JWA } from '../../lib/consts/index.js';

const mtlsKeys = JSON.parse(
  readFileSync('test/jwks/jwks.json', {
    encoding: 'utf-8',
  }),
);

const rsacrt = new X509Certificate(readFileSync('test/jwks/rsa.crt', { encoding: 'ascii' }));
const eccrt = new X509Certificate(readFileSync('test/jwks/ec.crt', { encoding: 'ascii' }));

const pqc = [];
for (const alg of ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']) {
  if (SubtleCrypto.supports?.('generateKey', alg)) {
    pqc.push(alg);
  }
}

const route = '/token';

const tokenAuthSucceeded = { success: true };

const introspectionAuthSucceeded = {
  active: false,
};

const tokenAuthRejected = {
  error: 'invalid_client',
  error_description: 'client authentication failed',
};

function errorDetail(spy) {
  return spy.args[0][1].error_detail;
}

function noW3A({ headers }) {
  assert.ok(!('www-authenticate' in Object(headers)));
}

const attestationPrivateKey = createPrivateKey({ format: 'jwk', key: clientKey });

function signAttestation(subject, instanceKeyPair, jwk = instanceKeyPair.publicKey.export({ format: 'jwk' })) {
  return new SignJWT({
    cnf: { jwk },
  })
    .setProtectedHeader({
      typ: 'oauth-client-attestation+jwt',
      alg: 'RS256',
    })
    .setSubject(subject)
    .setIssuedAt()
    .setExpirationTime('2h')
    .sign(attestationPrivateKey);
}

function signAttestationPop(provider, instanceKeyPair, challenge) {
  return new SignJWT({ challenge })
    .setProtectedHeader({
      typ: 'oauth-client-attestation-pop+jwt',
      alg: 'Ed25519',
    })
    .setAudience(provider.issuer)
    .setJti(nanoid())
    .setIssuedAt()
    .sign(instanceKeyPair.privateKey);
}

function signDpop(ctx, instanceKeyPair, nonce, path = route) {
  return new SignJWT({
    htu: `${ctx.provider.issuer}${ctx.suitePath(path)}`,
    htm: 'POST',
    nonce,
  })
    .setProtectedHeader({
      typ: 'dpop+jwt',
      alg: 'Ed25519',
      jwk: instanceKeyPair.publicKey.export({ format: 'jwk' }),
    })
    .setJti(nanoid())
    .setIssuedAt()
    .sign(instanceKeyPair.privateKey);
}

async function getCombinedHeaders(ctx, subject) {
  const response = await ctx.agent.post('/challenge').expect(200);
  const instanceKeyPair = generateKeyPairSync('ed25519');

  return {
    attestation: await signAttestation(subject, instanceKeyPair),
    dpop: await signDpop(ctx, instanceKeyPair, response.headers['dpop-nonce']),
  };
}

async function withAdditionalSecuritySignal(provider, value, fn) {
  const config = i(provider).configuration.features.attestClientAuth;
  const previous = config.additionalSecuritySignal;
  config.additionalSecuritySignal = value;
  try {
    await fn();
  } finally {
    config.additionalSecuritySignal = previous;
  }
}

describe('client authentication methods', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  afterEach(() => assertNoPendingInterceptors(), { timeout: 3000 });

  before(() => {
    fixture.provider.registerGrantType('foo', (ctx) => {
      ctx.body = { success: true };
    });
  }, { timeout: 3000 });

  describe('discovery', () => {
    const fixture1 = Object.create(fixture);

    it('pushes no algs when neither _jwt method is enabled', { timeout: 3000 }, () => {
      const provider = new Provider('http://localhost', {
        clientAuthMethods: [
          'none',
          'client_secret_basic',
          'client_secret_post',
        ],
      });

      assert.equal(i(provider).configuration.clientAuthSigningAlgValues, undefined);
    });

    it('removes client_secret_jwt when no HMAC based alg is enabled', { timeout: 3000 }, () => {
      const provider = new Provider('http://localhost', {
        clientAuthMethods: [
          'none',
          'client_secret_jwt',
          'private_key_jwt',
          'client_secret_basic',
          'client_secret_post',
        ],
        enabledJWA: {
          clientAuthSigningAlgValues: ['PS256'],
        },
      });

      assert.ok(!(i(provider).configuration.clientAuthMethods.has('client_secret_jwt')));
    });

    it('removes private_key_jwt when no public key crypto based alg is enabled', { timeout: 3000 }, () => {
      const provider = new Provider('http://localhost', {
        clientAuthMethods: [
          'none',
          'client_secret_jwt',
          'private_key_jwt',
          'client_secret_basic',
          'client_secret_post',
        ],
        enabledJWA: {
          clientAuthSigningAlgValues: ['HS256'],
        },
      });

      assert.ok(!(i(provider).configuration.clientAuthMethods.has('private_key_jwt')));
    });

    it('pushes only symmetric algs when client_secret_jwt is enabled', { timeout: 3000 }, () => {
      const provider = new Provider('http://localhost', {
        clientAuthMethods: [
          'none',
          'client_secret_basic',
          'client_secret_jwt',
          'client_secret_post',
        ],
        enabledJWA: cloneDeep({ ...JWA }),
      });

      const algs = [
        'HS256',
        'HS384',
        'HS512',
      ];

      assert.deepEqual(i(provider).configuration.clientAuthSigningAlgValues, algs);
    });

    it('pushes only asymmetric algs when private_key_jwt is enabled', { timeout: 3000 }, () => {
      const provider = new Provider('http://localhost', {
        clientAuthMethods: [
          'none',
          'client_secret_basic',
          'client_secret_post',
          'private_key_jwt',
        ],
        enabledJWA: cloneDeep({ ...JWA }),
      });

      const algs = [
        'RS256',
        'RS384',
        'RS512',
        'PS256',
        'PS384',
        'PS512',
        'ES256',
        'ES384',
        'ES512',
        'Ed25519',
        'EdDSA',
        ...pqc,
      ];

      assert.deepEqual(i(provider).configuration.clientAuthSigningAlgValues, algs);
    });

    it('pushes all algs when both _jwt methods are enabled', { timeout: 3000 }, () => {
      const provider = new Provider('http://localhost', {
        clientAuthMethods: [
          'none',
          'client_secret_basic',
          'client_secret_jwt',
          'client_secret_post',
          'private_key_jwt',
        ],
        enabledJWA: cloneDeep({ ...JWA }),
      });

      const algs = [
        'HS256',
        'HS384',
        'HS512',
        'RS256',
        'RS384',
        'RS512',
        'PS256',
        'PS384',
        'PS512',
        'ES256',
        'ES384',
        'ES512',
        'Ed25519',
        'EdDSA',
        ...pqc,
      ];

      assert.deepEqual(i(provider).configuration.clientAuthSigningAlgValues, algs);
    });

    it('does not advertise additional client attestation signal methods by default', { timeout: 3000 }, () => fixture1.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect(({ body }) => {
          assert.ok(!('client_attestation_pop_methods_supported' in Object(body)));
        }));

    it('advertises optional additional client attestation signal methods', { timeout: 3000 }, () => withAdditionalSecuritySignal(fixture1.provider, 'optional', async () => {
        await fixture1.agent.get('/.well-known/openid-configuration')
          .expect(200)
          .expect(({ body }) => {
            ((actual) => { assert.ok('client_attestation_pop_methods_supported' in Object(actual)); assert.deepEqual(actual.client_attestation_pop_methods_supported, ['attestation_pop_jwt', 'dpop_combined', 'none']); })(body);
          });
      }));

    it('advertises required additional client attestation signal methods', { timeout: 3000 }, () => withAdditionalSecuritySignal(fixture1.provider, 'required', async () => {
        await fixture1.agent.get('/.well-known/openid-configuration')
          .expect(200)
          .expect(({ body }) => {
            ((actual) => { assert.ok('client_attestation_pop_methods_supported' in Object(actual)); assert.deepEqual(actual.client_attestation_pop_methods_supported, ['attestation_pop_jwt', 'dpop_combined']); })(body);
          });
      }));

    it('does not advertise combined DPoP signals when DPoP is disabled', { timeout: 3000 }, () => withAdditionalSecuritySignal(fixture1.provider, 'optional', async () => {
        const { dPoP } = i(fixture1.provider).features;
        dPoP.enabled = false;
        try {
          await fixture1.agent.get('/.well-known/openid-configuration')
            .expect(200)
            .expect(({ body }) => {
              ((actual) => { assert.ok('client_attestation_pop_methods_supported' in Object(actual)); assert.deepEqual(actual.client_attestation_pop_methods_supported, ['attestation_pop_jwt', 'none']); })(body);
            });
        } finally {
          dPoP.enabled = true;
        }
      }));
  });

  it('expects auth to be provided', { timeout: 3000 }, () => fixture.agent.post(route)
      .send({})
      .type('form')
      .expect(400)
      .expect(noW3A)
      .expect({
        error: 'invalid_request',
        error_description: 'no client authentication mechanism provided',
      }));

  it('rejects when no client is found', { timeout: 3000 }, () => fixture.agent.post(route)
      .send({
        grant_type: 'foo',
        client_id: 'client-not-found',
      })
      .type('form')
      .expect(401)
      .expect(noW3A)
      .expect(tokenAuthRejected));

  describe('none "auth"', () => {
    const fixture2 = Object.create(fixture);

    it('accepts the "auth"', { timeout: 3000 }, () => fixture2.agent.post(route)
        .send({
          grant_type: 'foo',
          client_id: 'client-none',
        })
        .type('form')
        .expect(200)
        .expect(tokenAuthSucceeded));

    it('rejects the "auth" if secret was also provided', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture2.provider.once('grant.error', spy);
      return fixture2.agent.post(route)
        .send({
          grant_type: 'foo',
          client_id: 'client-none',
          client_secret: 'foobar',
        })
        .type('form')
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'the provided authentication mechanism does not match the registered client authentication method');
        })
        .expect(401)
        .expect(noW3A)
        .expect(tokenAuthRejected);
    });
  });

  describe('client_secret_basic auth', () => {
    const fixture3 = Object.create(fixture);

    it('accepts the auth', { timeout: 3000 }, () => fixture3.agent.post(route)
        .send({
          grant_type: 'foo',
        })
        .type('form')
        .auth('client-basic', 'secret')
        .expect(200)
        .expect(tokenAuthSucceeded));

    it('accepts the auth (but client configured with post)', { timeout: 3000 }, () => fixture3.agent.post(route)
        .send({
          grant_type: 'foo',
        })
        .type('form')
        .auth('client-post', 'secret')
        .expect(200)
        .expect(tokenAuthSucceeded));

    it('accepts the auth even with id in the body', { timeout: 3000 }, () => fixture3.agent.post(route)
        .send({
          grant_type: 'foo',
          client_id: 'client-basic',
        })
        .type('form')
        .auth('client-basic', 'secret')
        .expect(200)
        .expect(tokenAuthSucceeded));

    it('rejects the auth when body id differs', { timeout: 3000 }, () => fixture3.agent.post(route)
        .send({
          grant_type: 'foo',
          client_id: 'client-basic-other',
        })
        .type('form')
        .auth('client-basic', 'secret')
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_request',
          error_description: 'client_id mismatch',
        }));

    it('accepts the auth (https://www.rfc-editor.org/info/rfc6749/#appendix-B)', { timeout: 3000 }, () => fixture3.agent.post(route)
        .send({
          grant_type: 'foo',
        })
        .type('form')
        .auth(' %&+', ' %&+')
        .expect(200)
        .expect(tokenAuthSucceeded));

    it('accepts the auth (https://www.rfc-editor.org/info/rfc6749/#appendix-B again)', { timeout: 3000 }, () => fixture3.agent.post(route)
        .send({
          grant_type: 'foo',
        })
        .type('form')
        .auth('an:identifier', 'some secure & non-standard secret')
        .expect(200)
        .expect(tokenAuthSucceeded));

    it('rejects improperly encoded headers', { timeout: 3000 }, () => fixture3.agent.post(route)
        .send({
          grant_type: 'foo',
        })
        .type('form')
        .set('Authorization', `Basic ${btoa('foo with %:foo with $')}`)
        .expect({
          error: 'invalid_request',
          error_description: 'client_id and client_secret in the authorization header are not properly encoded',
        }));

    it('rejects a Basic credential containing non-base64 characters', { timeout: 3000 }, () => fixture3.agent.post(route)
        .send({
          grant_type: 'foo',
        })
        .type('form')
        .set('Authorization', `Basic ${btoa('client-basic:secret')}!`)
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_request',
          error_description: 'invalid authorization header value format',
        }));

    it('validates the Basic scheme format (parts)', { timeout: 3000 }, () => fixture3.agent.post(route)
        .send({
          grant_type: 'foo',
        })
        .type('form')
        .set('Authorization', 'Basic')
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_request',
          error_description: 'invalid authorization header value format',
        }));

    it('validates the Basic scheme format (Basic)', { timeout: 3000 }, () => fixture3.agent.post(route)
        .send({
          grant_type: 'foo',
        })
        .type('form')
        .auth('foo', { type: 'bearer' })
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_request',
          error_description: 'invalid authorization header value format',
        }));

    it('validates the Basic scheme format (no :)', { timeout: 3000 }, () => fixture3.agent.post(route)
        .send({
          grant_type: 'foo',
        })
        .type('form')
        .set('Authorization', 'Basic Zm9v')
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_request',
          error_description: 'invalid authorization header value format',
        }));

    it('rejects invalid secrets', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture3.provider.once('grant.error', spy);
      return fixture3.agent.post(route)
        .send({
          grant_type: 'foo',
        })
        .type('form')
        .auth('client-basic', 'invalid secret')
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'invalid secret provided');
        })
        .expect(fixture3.failWith(401, tokenAuthRejected.error, tokenAuthRejected.error_description, undefined, 'Basic'));
    });

    it('rejects double auth', { timeout: 3000 }, () => fixture3.agent.post(route)
        .send({
          grant_type: 'foo',
          client_id: 'client-basic',
          client_secret: 'secret',
        })
        .type('form')
        .auth('client-basic', 'invalid secret')
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_request',
          error_description: 'client authentication must only be provided using one mechanism',
        }));

    it('rejects double auth (no client_id in body)', { timeout: 3000 }, () => fixture3.agent.post(route)
        .send({
          grant_type: 'foo',
          client_secret: 'secret',
        })
        .type('form')
        .auth('client-basic', 'invalid secret')
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_request',
          error_description: 'client authentication must only be provided using one mechanism',
        }));

    it('requires the client_secret to be sent', { timeout: 3000 }, () => fixture3.agent.post(route)
        .send({
          grant_type: 'foo',
        })
        .type('form')
        .auth('client-basic', '')
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_request',
          error_description: 'client_secret must be provided in the Authorization header',
        }));

    it('rejects expired secrets', { timeout: 3000 }, () => fixture3.agent.post(route)
        .send({
          grant_type: 'foo',
        })
        .type('form')
        .auth('secret-expired-basic', 'secret')
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_client',
          error_description: 'could not authenticate the client - its client secret is expired',
        }));
  });

  describe('client_secret_post auth', () => {
    const fixture4 = Object.create(fixture);

    it('accepts the auth', { timeout: 3000 }, () => fixture4.agent.post(route)
        .send({
          grant_type: 'foo',
          client_id: 'client-post',
          client_secret: 'secret',
        })
        .type('form')
        .expect(200)
        .expect(tokenAuthSucceeded));

    it('can use transfer-encoding: chunked', { timeout: 3000 }, (_t, done) => {
      const { address, port } = globalThis.server.address();

      const req = request({
        hostname: address,
        port,
        path: fixture4.suitePath(route),
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Transfer-Encoding': 'chunked',
        },
      }, (res) => {
        let data = '';

        res.on('data', (chunk) => {
          data += chunk;
        });

        res.on('end', () => {
          try {
            assert.deepEqual(JSON.parse(data), tokenAuthSucceeded);
            done();
          } catch (err) {
            done(err);
          }
        });

        res.on('error', done);
      });

      req.write('grant_type=foo&client_id');
      req.write('=client-post&client_secret=secret');
      req.end();
      req.on('error', done);
    });

    it('accepts the auth (but client configured with basic)', { timeout: 3000 }, () => fixture4.agent.post(route)
        .send({
          grant_type: 'foo',
          client_id: 'client-basic',
          client_secret: 'secret',
        })
        .type('form')
        .expect(200)
        .expect(tokenAuthSucceeded));

    it('rejects invalid secrets', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture4.provider.once('grant.error', spy);
      return fixture4.agent.post(route)
        .send({
          grant_type: 'foo',
          client_id: 'client-post',
          client_secret: 'invalid',
        })
        .type('form')
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'invalid secret provided');
        })
        .expect(401)
        .expect(noW3A)
        .expect(tokenAuthRejected);
    });

    it('requires the client_secret to be sent', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture4.provider.once('grant.error', spy);
      return fixture4.agent.post(route)
        .send({
          grant_type: 'foo',
          client_id: 'client-post',
          client_secret: '',
        })
        .type('form')
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'the provided authentication mechanism does not match the registered client authentication method');
        })
        .expect(401)
        .expect(noW3A)
        .expect(tokenAuthRejected);
    });

    it('rejects expired secrets', { timeout: 3000 }, () => fixture4.agent.post(route)
        .send({
          grant_type: 'foo',
          client_id: 'secret-expired-basic',
          client_secret: 'secret',
        })
        .type('form')
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_client',
          error_description: 'could not authenticate the client - its client secret is expired',
        }));
  });

  describe('client_secret_jwt auth', () => {
    const fixture5 = Object.create(fixture);

    before(async () => {
      fixture5.key = await importJWK((await fixture5.provider.Client.find('client-jwt-secret')).symmetricKeyStore.selectForSign({ alg: 'HS256' })[0]);
    }, { timeout: 3000 });

    it('accepts the auth', { timeout: 3000 }, () => JWT.sign({
        jti: nanoid(),
        aud: fixture5.provider.issuer,
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, fixture5.key, 'HS256', { expiresIn: 60 }).then((assertion) => fixture5.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'foo',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect(tokenAuthSucceeded)));

    describe('additional audience values', () => {
      const fixture6 = Object.create(fixture5);

      it('accepts the auth when aud is an array', { timeout: 3000 }, () => JWT.sign({
          jti: nanoid(),
          aud: [fixture6.provider.issuer],
          sub: 'client-jwt-secret',
          iss: 'client-jwt-secret',
        }, fixture6.key, 'HS256', { expiresIn: 60 }).then((assertion) => fixture6.agent.post(route)
          .send({
            client_assertion: assertion,
            grant_type: 'foo',
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          })
          .type('form')
          .expect(tokenAuthSucceeded)));

      it('rejects an aud array containing a non-string member', { timeout: 3000 }, () => JWT.sign({
          jti: nanoid(),
          aud: [fixture6.provider.issuer, null],
          sub: 'client-jwt-secret',
          iss: 'client-jwt-secret',
        }, fixture6.key, 'HS256', { expiresIn: 60 }).then((assertion) => fixture6.agent.post(route)
          .send({
            client_assertion: assertion,
            grant_type: 'foo',
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          })
          .type('form')
          .expect(401)
          .expect(tokenAuthRejected)));

      it('accepts the auth when aud is the token endpoint', { timeout: 3000 }, async () => {
        for (const aud of [fixture6.provider.issuer + fixture6.suitePath('/token'), [fixture6.provider.issuer + fixture6.suitePath('/token')]]) {
          await JWT.sign({
            jti: nanoid(),
            aud,
            sub: 'client-jwt-secret',
            iss: 'client-jwt-secret',
          }, fixture6.key, 'HS256', { expiresIn: 60 }).then((assertion) => fixture6.agent.post(route)
            .send({
              client_assertion: assertion,
              grant_type: 'foo',
              client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            })
            .type('form')
            .expect(tokenAuthSucceeded));
        }
      });

      it('accepts the auth when aud is the token endpoint at another endpoint', { timeout: 3000 }, async () => {
        for (const aud of [fixture6.provider.issuer + fixture6.suitePath('/token'), [fixture6.provider.issuer + fixture6.suitePath('/token')]]) {
          await JWT.sign({
            jti: nanoid(),
            aud,
            sub: 'client-jwt-secret',
            iss: 'client-jwt-secret',
          }, fixture6.key, 'HS256', { expiresIn: 60 }).then((assertion) => fixture6.agent.post('/token/introspection')
            .send({
              client_assertion: assertion,
              client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
              token: 'foo',
            })
            .type('form')
            .expect(introspectionAuthSucceeded));
        }
      });

      it('accepts the auth when aud is the url of another endpoint it is used at', { timeout: 3000 }, async () => {
        for (const aud of [fixture6.provider.issuer + fixture6.suitePath('/token/introspection'), [fixture6.provider.issuer + fixture6.suitePath('/token/introspection')]]) {
          await JWT.sign({
            jti: nanoid(),
            aud,
            sub: 'client-jwt-secret',
            iss: 'client-jwt-secret',
          }, fixture6.key, 'HS256', { expiresIn: 60 }).then((assertion) => fixture6.agent.post('/token/introspection')
            .send({
              client_assertion: assertion,
              client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
              token: 'foo',
            })
            .type('form')
            .expect(introspectionAuthSucceeded));
        }
      });
    });

    it('rejects the auth if this is actually a none-client', { timeout: 3000 }, async () => {
      const spy = sinon.spy();
      fixture5.provider.once('grant.error', spy);
      return JWT.sign({
        jti: nanoid(),
        aud: fixture5.provider.issuer,
        sub: 'client-none',
        iss: 'client-none',
      }, fixture5.key, 'HS256', { expiresIn: 60 }).then((assertion) => fixture5.agent.post(route)
        .send({
          client_id: 'client-none',
          client_assertion: assertion,
          grant_type: 'foo',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect(401)
        .expect(noW3A)
        .expect(tokenAuthRejected)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'the provided authentication mechanism does not match the registered client authentication method');
        }));
    });

    it('rejects the auth if authorization header is also present', { timeout: 3000 }, () => JWT.sign({
        jti: nanoid(),
        aud: fixture5.provider.issuer,
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, fixture5.key, 'HS256', { expiresIn: 60 }).then((assertion) => fixture5.agent.post(route)
        .auth('client-basic', 'secret')
        .send({
          client_assertion: assertion,
          grant_type: 'foo',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_request',
          error_description: 'client authentication must only be provided using one mechanism',
        })));

    it('rejects the auth if client secret is also present', { timeout: 3000 }, () => JWT.sign({
        jti: nanoid(),
        aud: fixture5.provider.issuer,
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, fixture5.key, 'HS256', { expiresIn: 60 }).then((assertion) => fixture5.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'foo',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_secret: 'foo',
        })
        .type('form')
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_request',
          error_description: 'client authentication must only be provided using one mechanism',
        })));

    it('rejects malformed assertions', { timeout: 3000 }, () => fixture5.agent.post(route)
        .send({
          client_id: 'client-jwt-secret',
          client_assertion: '.eyJzdWIiOiJjbGllbnQtand0LXNlY3JldCIsImFsZyI6IkhTMjU2In0.',
          grant_type: 'foo',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect(401)
        .expect(noW3A)
        .expect(tokenAuthRejected));

    it('rejects an assertion whose protected header is JSON null', { timeout: 3000 }, () => {
      const signingInput = [
        Buffer.from('null').toString('base64url'),
        Buffer.from(JSON.stringify({
          aud: fixture5.provider.issuer,
          exp: Math.floor(Date.now() / 1000) + 60,
          iss: 'client-jwt-secret',
          jti: nanoid(),
          sub: 'client-jwt-secret',
        })).toString('base64url'),
      ].join('.');
      return fixture5.agent.post(route)
        .send({
          client_assertion: `${signingInput}.invalid-signature`,
          grant_type: 'foo',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect(401)
        .expect(noW3A)
        .expect(tokenAuthRejected);
    });

    it('exp must be set', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture5.provider.once('grant.error', spy);
      return JWT.sign({
        jti: nanoid(),
        aud: fixture5.provider.issuer,
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
        exp: '',
      }, fixture5.key, 'HS256', {
        // expiresIn: 60
      }).then((assertion) => fixture5.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'foo',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect(401)
        .expect(noW3A)
        .expect(tokenAuthRejected)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'expiration must be specified in the client_assertion JWT');
        }));
    });

    it('aud must be set', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture5.provider.once('grant.error', spy);
      return JWT.sign({
        jti: nanoid(),
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, fixture5.key, 'HS256', {
        expiresIn: 60,
      }).then((assertion) => fixture5.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'foo',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect(401)
        .expect(noW3A)
        .expect(tokenAuthRejected)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'aud (JWT audience) must be provided in the client_assertion JWT');
        }));
    });

    it('jti must be set', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture5.provider.once('grant.error', spy);
      return JWT.sign({
        // jti: nanoid(),
        aud: fixture5.provider.issuer,
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, fixture5.key, 'HS256', {
        expiresIn: 60,
      }).then((assertion) => fixture5.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'foo',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect(401)
        .expect(noW3A)
        .expect(tokenAuthRejected)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'unique jti (JWT ID) must be provided in the client_assertion JWT');
        }));
    });

    it('iss must be set', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture5.provider.once('grant.error', spy);
      return JWT.sign({
        jti: nanoid(),
        aud: fixture5.provider.issuer,
        sub: 'client-jwt-secret',
        // iss: 'client-jwt-secret',
      }, fixture5.key, 'HS256', {
        expiresIn: 60,
      }).then((assertion) => fixture5.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'foo',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect(401)
        .expect(noW3A)
        .expect(tokenAuthRejected)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'iss (JWT issuer) must be provided in the client_assertion JWT');
        }));
    });

    it('sub must be set', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture5.provider.once('grant.error', spy);
      return JWT.sign({
        jti: nanoid(),
        aud: fixture5.provider.issuer,
        // sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, fixture5.key, 'HS256', {
        expiresIn: 60,
      }).then((assertion) => fixture5.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'foo',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect(401)
        .expect(noW3A)
        .expect(tokenAuthRejected)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'sub (JWT subject) must be provided in the client_assertion JWT');
        }));
    });

    it('iss must be the client id', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture5.provider.once('grant.error', spy);
      return JWT.sign({
        jti: nanoid(),
        aud: fixture5.provider.issuer,
        sub: 'client-jwt-secret',
        iss: 'not equal to clientid',
      }, fixture5.key, 'HS256', {
        expiresIn: 60,
      }).then((assertion) => fixture5.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'foo',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect(401)
        .expect(noW3A)
        .expect(tokenAuthRejected)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'iss (JWT issuer) must be the client_id');
        }));
    });

    it('checks for mismatch in client_assertion client_id and body client_id', { timeout: 3000 }, () => JWT.sign({
        jti: nanoid(),
        aud: fixture5.provider.issuer,
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, fixture5.key, 'HS256', { expiresIn: 60 }).then((assertion) => fixture5.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'foo',
          client_id: 'mismatching-client-id',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_request',
          error_description: 'client_id mismatch',
        })));

    it('requires client_assertion_type', { timeout: 3000 }, () => JWT.sign({
        jti: nanoid(),
        aud: fixture5.provider.issuer,
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, fixture5.key, 'HS256', {
        expiresIn: 60,
      }).then((assertion) => fixture5.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'foo',
        // client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        })
        .type('form')
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_request',
          error_description: 'client_assertion_type must be provided',
        })));

    it('requires client_assertion_type of specific value', { timeout: 3000 }, () => JWT.sign({
        jti: nanoid(),
        aud: fixture5.provider.issuer,
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, fixture5.key, 'HS256', {
        expiresIn: 60,
      }).then((assertion) => fixture5.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'foo',
          client_assertion_type: 'urn:ietf:mycustom',
        })
        .type('form')
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_request',
          error_description: 'client_assertion_type must have value urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })));

    it('rejects invalid assertions', { timeout: 3000 }, () => fixture5.agent.post(route)
        .send({
          client_assertion: 'this.notatall.valid',
          grant_type: 'foo',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_request',
          error_description: 'invalid client_assertion format',
        }));

    it('rejects valid format and signature but expired/invalid jwts', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture5.provider.once('grant.error', spy);
      return JWT.sign({
        jti: nanoid(),
        aud: fixture5.provider.issuer,
        sub: 'client-jwt-secret',
        iss: 'client-jwt-secret',
      }, fixture5.key, 'HS256', {
        expiresIn: -300,
      }).then((assertion) => fixture5.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'foo',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect(401)
        .expect(noW3A)
        .expect(tokenAuthRejected)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'jwt expired');
        }));
    });

    it('rejects assertions when the secret is expired', { timeout: 3000 }, async () => {
      const key = await importJWK((await fixture5.provider.Client.find('secret-expired-jwt')).symmetricKeyStore.selectForSign({ alg: 'HS256' })[0]);
      return JWT.sign({
        jti: nanoid(),
        aud: fixture5.provider.issuer,
        sub: 'secret-expired-jwt',
        iss: 'secret-expired-jwt',
      }, key, 'HS256', {
        expiresIn: -1,
      }).then((assertion) => fixture5.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'foo',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_client',
          error_description: 'could not authenticate the client - its client secret used for the client_assertion is expired',
        }));
    });

    describe('JTI uniqueness', () => {
      const fixture7 = Object.create(fixture5);

      it('rejects replay until a fractional expiration is no longer accepted', { timeout: 3000 }, async (t) => {
        const issuedAt = Math.floor(Date.now() / 1000);
        let now = issuedAt * 1000;
        t.mock.method(Date, 'now', () => now);
        const { clockTolerance } = i(fixture7.provider).configuration;
        const exp = issuedAt + 10.5;
        const assertion = await JWT.sign({
          jti: nanoid(),
          aud: fixture7.provider.issuer,
          sub: 'client-jwt-secret',
          iss: 'client-jwt-secret',
          exp,
        }, fixture7.key, 'HS256');
        const adapter = fixture7.provider.ReplayDetection.adapter;
        // The shared test adapter does not expire entries according to their storage TTL.
        const expiring = createMemoryAdapter(0)('ReplayDetection');
        t.mock.method(adapter, 'find', expiring.find.bind(expiring));
        t.mock.method(adapter, 'upsert', expiring.upsert.bind(expiring));
        const authenticate = () => fixture7.agent.post(route)
          .send({
            client_assertion: assertion,
            grant_type: 'foo',
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          })
          .type('form');

        await authenticate().expect(200).expect(tokenAuthSucceeded);

        now = (exp + clockTolerance + 0.1) * 1000;
        const replay = sinon.spy();
        fixture7.provider.once('grant.error', replay);
        await authenticate().expect(401).expect(tokenAuthRejected);
        assert.equal(replay.calledOnce, true);
        assert.equal(errorDetail(replay), 'client assertion tokens must only be used once');

        now = Math.ceil(exp + clockTolerance) * 1000;
        const expired = sinon.spy();
        fixture7.provider.once('grant.error', expired);
        await authenticate().expect(401).expect(tokenAuthRejected);
        assert.equal(expired.calledOnce, true);
        assert.equal(errorDetail(expired), 'jwt expired');
      });

      it('fails closed when an atomic adapter rejects concurrent assertion reuse', { timeout: 3000 }, async () => {
        const assertion = await JWT.sign({
          jti: nanoid(),
          aud: fixture7.provider.issuer,
          sub: 'client-jwt-secret',
          iss: 'client-jwt-secret',
        }, fixture7.key, 'HS256', { expiresIn: 60 });
        const adapter = fixture7.provider.ReplayDetection.adapter;
        const find = adapter.find.bind(adapter);
        const upsert = adapter.upsert.bind(adapter);
        const claims = new Set();
        const duplicate = new Error('replay identifier already exists');
        let lookups = 0;
        let release;
        const ready = new Promise((resolve) => { release = resolve; });
        const findStub = sinon.stub(adapter, 'find').callsFake(async (id) => {
          const found = await find(id);
          assert.equal(found, undefined);
          lookups += 1;
          if (lookups === 2) release();
          await ready;
          return found;
        });
        const upsertStub = sinon.stub(adapter, 'upsert').callsFake((id, payload, expiresIn) => {
          if (claims.has(id)) throw duplicate;
          claims.add(id);
          return upsert(id, payload, expiresIn);
        });

        try {
          const responses = await Promise.all([0, 1].map(() => fixture7.agent.post(route)
            .send({
              client_assertion: assertion,
              grant_type: 'foo',
              client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            })
            .type('form')));

          assert.deepEqual(responses.map(({ status }) => status).sort(), [200, 500]);
          assert.deepEqual(responses.find(({ status }) => status === 200).body, tokenAuthSucceeded);
          assert.deepEqual(responses.find(({ status }) => status === 500).body, {
            error: 'server_error',
            error_description: 'oops! something went wrong',
          });
          assert.equal(findStub.callCount, 2);
          assert.equal(upsertStub.callCount, 2);
          assert.equal(claims.size, 1);
        } finally {
          findStub.restore();
          upsertStub.restore();
        }
      });

      it('reused jtis must be rejected', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        return JWT.sign({
          jti: nanoid(),
          aud: fixture7.provider.issuer,
          sub: 'client-jwt-secret',
          iss: 'client-jwt-secret',
        }, fixture7.key, 'HS256', {
          expiresIn: 60,
        })
          .then((assertion) => fixture7.agent.post(route)
            .send({
              client_assertion: assertion,
              grant_type: 'foo',
              client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            })
            .type('form')
            .expect(tokenAuthSucceeded)
            .then(() => {
              fixture7.provider.once('grant.error', spy);
            })
            .then(() => fixture7.agent.post(route)
              .send({
                client_assertion: assertion,
                grant_type: 'foo',
                client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
              })
              .type('form')
              .expect(401)
              .expect(noW3A)
              .expect(tokenAuthRejected)
              .expect(() => {
                assert.equal(spy.calledOnce, true);
                assert.equal(errorDetail(spy), 'client assertion tokens must only be used once');
              })));
      });
    });

    describe('when token_endpoint_auth_signing_alg is set on the client', () => {
      const fixture8 = Object.create(fixture5);

      before(async () => {
        (await fixture8.provider.Client.find('client-jwt-secret')).tokenEndpointAuthSigningAlg = 'HS384';
      }, { timeout: 3000 });
      after(async () => {
        delete (await fixture8.provider.Client.find('client-jwt-secret')).tokenEndpointAuthSigningAlg;
      }, { timeout: 3000 });
      it('rejects signatures with different algorithm', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture8.provider.once('grant.error', spy);
        return JWT.sign({
          jti: nanoid(),
          aud: fixture8.provider.issuer,
          sub: 'client-jwt-secret',
          iss: 'client-jwt-secret',
        }, fixture8.key, 'HS256', {
          expiresIn: 60,
        }).then((assertion) => fixture8.agent.post(route)
          .send({
            client_assertion: assertion,
            grant_type: 'foo',
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          })
          .type('form')
          .expect(401)
          .expect(noW3A)
          .expect(tokenAuthRejected)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
            assert.equal(errorDetail(spy), 'alg mismatch');
          }));
      });
    });
  });

  describe('private_key_jwt auth', () => {
    const fixture9 = Object.create(fixture);

    const privateKey = createPrivateKey({ format: 'jwk', key: clientKey });

    after(() => {
      i(fixture9.provider).configuration.clockTolerance = 0;
    }, { timeout: 3000 });

    it('accepts the auth', { timeout: 3000 }, () => JWT.sign({
        jti: nanoid(),
        aud: fixture9.provider.issuer,
        sub: 'client-jwt-key',
        iss: 'client-jwt-key',
      }, privateKey, 'RS256', {
        expiresIn: 60,
      }).then((assertion) => fixture9.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'foo',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect(tokenAuthSucceeded)));

    it('accepts client assertions issued within acceptable system clock skew', { timeout: 3000 }, () => {
      i(fixture9.provider).configuration.clockTolerance = 10;
      return JWT.sign({
        jti: nanoid(),
        aud: fixture9.provider.issuer,
        sub: 'client-jwt-key',
        iss: 'client-jwt-key',
        iat: Math.ceil(Date.now() / 1000) + 5,
      }, privateKey, 'RS256', {
        expiresIn: 60,
      }).then((assertion) => fixture9.agent.post(route)
        .send({
          client_assertion: assertion,
          grant_type: 'foo',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        })
        .type('form')
        .expect(tokenAuthSucceeded));
    });
  });

  describe('client attestation as an additional security signal', () => {
    const fixture10 = Object.create(fixture);

    async function getSignalHeaders(ctx, subject) {
      const { body: { attestation_challenge: challenge } } = await ctx.agent.post('/challenge');
      const instanceKeyPair = generateKeyPairSync('ed25519');

      return {
        attestation: await signAttestation(subject, instanceKeyPair),
        pop: await signAttestationPop(ctx.provider, instanceKeyPair, challenge),
      };
    }

    it('rejects client_secret_basic with attestation headers when the signal is disabled', { timeout: 3000 }, async () => {
      const { attestation, pop } = await getSignalHeaders(fixture10, 'client-basic');

      await fixture10.agent.post(route)
        .auth('client-basic', 'secret')
        .set('OAuth-Client-Attestation', attestation)
        .set('OAuth-Client-Attestation-PoP', pop)
        .send({ grant_type: 'foo' })
        .type('form')
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_request',
          error_description: 'client authentication must only be provided using one mechanism',
        });
    });

    it('rejects none auth with attestation headers when the signal is disabled', { timeout: 3000 }, async () => {
      const { attestation, pop } = await getSignalHeaders(fixture10, 'client-none');

      await fixture10.agent.post(route)
        .set('OAuth-Client-Attestation', attestation)
        .set('OAuth-Client-Attestation-PoP', pop)
        .send({
          grant_type: 'foo',
          client_id: 'client-none',
        })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_request',
          error_description: 'client authentication must only be provided using one mechanism',
        });
    });

    it('accepts client_secret_basic with an optional signal', { timeout: 3000 }, () => withAdditionalSecuritySignal(fixture10.provider, 'optional', async () => {
        const { attestation, pop } = await getSignalHeaders(fixture10, 'client-basic');
        const spy = sinon.spy();
        fixture10.provider.once('grant.success', spy);

        await fixture10.agent.post(route)
          .auth('client-basic', 'secret')
          .set('OAuth-Client-Attestation', attestation)
          .set('OAuth-Client-Attestation-PoP', pop)
          .send({ grant_type: 'foo' })
          .type('form')
          .expect(200)
          .expect(tokenAuthSucceeded)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
            ((actual) => { assert.ok("method" in Object(actual)); assert.equal(actual.method, 'attestation_pop_jwt'); assert.ok("signal" in Object(actual)); assert.equal(actual.signal, true); })(spy.firstCall.args[0].oidc.clientAttestation);
            ((actual) => { assert.ok('sub' in Object(actual)); assert.equal(actual.sub, 'client-basic'); })(spy.firstCall.args[0].oidc.clientAttestation.attestation.payload);
          });
      }));

    it('accepts none auth with a required signal', { timeout: 3000 }, () => withAdditionalSecuritySignal(fixture10.provider, 'required', async () => {
        const { attestation, pop } = await getSignalHeaders(fixture10, 'client-none');

        await fixture10.agent.post(route)
          .set('OAuth-Client-Attestation', attestation)
          .set('OAuth-Client-Attestation-PoP', pop)
          .send({
            grant_type: 'foo',
            client_id: 'client-none',
          })
          .type('form')
          .expect(200)
          .expect(tokenAuthSucceeded);
      }));

    for (const [method, clientId, alg] of [
      ['client_secret_jwt', 'client-jwt-secret', 'HS256'],
      ['private_key_jwt', 'client-jwt-key', 'RS256'],
    ]) {
      for (const proofMethod of ['attestation_pop_jwt', 'dpop_combined']) {
        for (const value of ['optional', 'required']) {
          it(`accepts ${method} without client_id with ${value} ${proofMethod} signal`, { timeout: 3000 }, () => withAdditionalSecuritySignal(fixture10.provider, value, async () => {
              const key = alg === 'RS256' ? attestationPrivateKey : await importJWK(
                (await fixture10.provider.Client.find(clientId)).symmetricKeyStore.selectForSign({ alg })[0],
              );
              const assertion = await JWT.sign({
                jti: nanoid(),
                aud: fixture10.provider.issuer,
                sub: clientId,
                iss: clientId,
              }, key, alg, { expiresIn: 60 });
              const { attestation, pop, dpop } = await (proofMethod === 'dpop_combined'
                ? getCombinedHeaders(fixture10, clientId) : getSignalHeaders(fixture10, clientId));
              const spy = sinon.spy();
              fixture10.provider.once('grant.success', spy);

              await fixture10.agent.post(route)
                .set('OAuth-Client-Attestation', attestation)
                .set(pop ? 'OAuth-Client-Attestation-PoP' : 'DPoP', pop || dpop)
                .send({
                  client_assertion: assertion,
                  client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                  grant_type: 'foo',
                })
                .type('form')
                .expect(200)
                .expect(tokenAuthSucceeded)
                .expect(() => {
                  assert.equal(spy.calledOnce, true);
                  ((actual) => { assert.ok("method" in Object(actual)); assert.equal(actual.method, proofMethod); assert.ok("signal" in Object(actual)); assert.equal(actual.signal, true); })(spy.firstCall.args[0].oidc.clientAttestation);
                });
            }));
        }
      }
    }

    for (const value of ['optional', 'required']) {
      it(`accepts client_secret_basic with a ${value} combined DPoP signal`, { timeout: 3000 }, () => withAdditionalSecuritySignal(fixture10.provider, value, async () => {
          const { attestation, dpop } = await getCombinedHeaders(fixture10, 'client-basic');
          const spy = sinon.spy();
          fixture10.provider.once('grant.success', spy);

          await fixture10.agent.post(route)
            .auth('client-basic', 'secret')
            .set('OAuth-Client-Attestation', attestation)
            .set('DPoP', dpop)
            .send({ grant_type: 'foo' })
            .type('form')
            .expect(200)
            .expect(tokenAuthSucceeded)
            .expect(() => {
              assert.equal(spy.calledOnce, true);
              ((actual) => { assert.ok("method" in Object(actual)); assert.equal(actual.method, 'dpop_combined'); assert.ok("signal" in Object(actual)); assert.equal(actual.signal, true); })(spy.firstCall.args[0].oidc.clientAttestation);
              ((actual) => { assert.ok('sub' in Object(actual)); assert.equal(actual.sub, 'client-basic'); })(spy.firstCall.args[0].oidc.clientAttestation.attestation.payload);
            });
        }));
    }

    it('rejects when a required signal is missing', { timeout: 3000 }, () => withAdditionalSecuritySignal(fixture10.provider, 'required', async () => {
        const spy = sinon.spy();
        fixture10.provider.once('grant.error', spy);

        await fixture10.agent.post(route)
          .auth('client-basic', 'secret')
          .send({ grant_type: 'foo' })
          .type('form')
          .expect(400)
          .expect(noW3A)
          .expect({ error: 'invalid_client_attestation' })
          .expect(() => {
            assert.equal(spy.calledOnce, true);
            assert.equal(errorDetail(spy), 'oauth-client-attestation missing');
          });
      }));

    it('rejects a partial optional signal', { timeout: 3000 }, () => withAdditionalSecuritySignal(fixture10.provider, 'optional', async () => {
        const { attestation } = await getSignalHeaders(fixture10, 'client-basic');
        const spy = sinon.spy();
        fixture10.provider.once('grant.error', spy);

        await fixture10.agent.post(route)
          .auth('client-basic', 'secret')
          .set('OAuth-Client-Attestation', attestation)
          .send({ grant_type: 'foo' })
          .type('form')
          .expect(400)
          .expect({ error: 'invalid_client_attestation' })
          .expect(() => {
            assert.equal(spy.calledOnce, true);
            assert.equal(errorDetail(spy), 'oauth-client-attestation-pop missing');
          });
      }));

    it('rejects when the signal subject does not match the authenticated client', { timeout: 3000 }, () => withAdditionalSecuritySignal(fixture10.provider, 'optional', async () => {
        const { attestation, pop } = await getSignalHeaders(fixture10, 'client-none');
        const spy = sinon.spy();
        fixture10.provider.once('grant.error', spy);

        await fixture10.agent.post(route)
          .auth('client-basic', 'secret')
          .set('OAuth-Client-Attestation', attestation)
          .set('OAuth-Client-Attestation-PoP', pop)
          .send({ grant_type: 'foo' })
          .type('form')
          .expect(400)
          .expect({ error: 'invalid_client_attestation' })
          .expect(() => {
            assert.equal(spy.calledOnce, true);
            const err = spy.args[0][1];
            assert.ok(err.cause instanceof Error);
            assert.equal(errorDetail(spy), err.cause.message);
          });
      }));
  });

  describe('attest_jwt_client_auth auth', () => {
    const fixture11 = Object.create(fixture);

    let challenge;
    before(async () => {
      const response = await fixture11.agent.post('/challenge');
      assert.ok('attestation_challenge' in Object(response.body));
      assert.equal(response.headers['oauth-client-attestation-challenge'], response.body.attestation_challenge);
      challenge = response.body.attestation_challenge;
    }, { timeout: 3000 });

    const privateKey = createPrivateKey({ format: 'jwk', key: clientKey });
    const instanceKeyPair = generateKeyPairSync('ed25519');

    it('accepts the auth', { timeout: 3000 }, async () => {
      const [attestation, pop] = await Promise.all([
        new SignJWT({
          cnf: {
            jwk: instanceKeyPair.publicKey.export({ format: 'jwk' }),
          },
        })
          .setProtectedHeader({
            typ: 'oauth-client-attestation+jwt',
            alg: 'RS256',
          })
          .setSubject('attest_jwt_client_auth')
          .setIssuedAt()
          .setExpirationTime('2h')
          .sign(privateKey),
        new SignJWT({ challenge })
          .setProtectedHeader({
            typ: 'oauth-client-attestation-pop+jwt',
            alg: 'Ed25519',
          })
          .setAudience(fixture11.provider.issuer)
          .setJti(nanoid())
          .setIssuedAt()
          .sign(instanceKeyPair.privateKey),
      ]);

      return fixture11.agent.post(route)
        .set('OAuth-Client-Attestation', attestation)
        .set('OAuth-Client-Attestation-PoP', pop)
        .send({
          grant_type: 'foo',
        })
        .type('form')
        .expect(tokenAuthSucceeded);
    });

    describe('oauth-client-attestation', () => {
      const fixture12 = Object.create(fixture11);

      before(() => {
        fixture12.signPop = () => new SignJWT({ challenge })
          .setProtectedHeader({
            typ: 'oauth-client-attestation-pop+jwt',
            alg: 'Ed25519',
          })
          .setAudience(fixture12.provider.issuer)
          .setJti(nanoid())
          .setIssuedAt()
          .sign(instanceKeyPair.privateKey);
      }, { timeout: 3000 });

      it('requires the iat claim', { timeout: 3000 }, async () => {
        const attestation = await new SignJWT({
          cnf: {
            jwk: instanceKeyPair.publicKey.export({ format: 'jwk' }),
          },
        })
          .setProtectedHeader({
            typ: 'oauth-client-attestation+jwt',
            alg: 'RS256',
          })
          .setSubject('attest_jwt_client_auth')
          .setExpirationTime('2h')
          .sign(privateKey);
        const spy = sinon.spy();
        fixture12.provider.once('grant.error', spy);

        await fixture12.agent.post(route)
          .set('OAuth-Client-Attestation', attestation)
          .set('OAuth-Client-Attestation-PoP', await fixture12.signPop())
          .send({ grant_type: 'foo' })
          .type('form')
          .expect(401)
          .expect(tokenAuthRejected)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
            assert.equal(errorDetail(spy), 'missing required "iat" claim');
          });
      });

      it('checks all required properties and their values', { timeout: 3000 }, async () => {
        for (const attestation of await Promise.all([
          new SignJWT({
            cnf: {
              jwk: instanceKeyPair.publicKey.export({ format: 'jwk' }),
            },
          })
            .setProtectedHeader({
              typ: 'oauth-client-attestation+jwt',
              alg: 'RS256',
            })
            // .setSubject('attest_jwt_client_auth')
            .setIssuedAt()
            .setExpirationTime('2h')
            .sign(privateKey),
          new SignJWT({
            cnf: {
              jwk: instanceKeyPair.publicKey.export({ format: 'jwk' }),
            },
          })
            .setProtectedHeader({
              typ: 'oauth-client-attestation+jwt',
              alg: 'RS256',
            })
            .setSubject('foo')
            .setIssuedAt()
            .setExpirationTime('2h')
            .sign(privateKey),
          new SignJWT({
            cnf: {
              jwk: instanceKeyPair.publicKey.export({ format: 'jwk' }),
            },
          })
            .setProtectedHeader({
              typ: 'oauth-client-attestation+jwt',
              alg: 'RS256',
            })
            .setSubject('attest_jwt_client_auth')
            .setIssuedAt()
            // .setExpirationTime('2h')
            .sign(privateKey),
          new SignJWT({
            cnf: {
              jwk: instanceKeyPair.publicKey.export({ format: 'jwk' }),
            },
          })
            .setProtectedHeader({
              typ: 'oauth-client-attestation+jwt',
              alg: 'RS256',
            })
            .setSubject('attest_jwt_client_auth')
            .setIssuedAt()
            .setExpirationTime(0)
            .sign(privateKey),
          new SignJWT({
            cnf: {
              // jwk: instanceKeyPair.publicKey.export({ format: 'jwk' }),
            },
          })
            .setProtectedHeader({
              typ: 'oauth-client-attestation+jwt',
              alg: 'RS256',
            })
            .setSubject('attest_jwt_client_auth')
            .setIssuedAt()
            .setExpirationTime('2h')
            .sign(privateKey),
          new SignJWT({
            // cnf: {
            //   jwk: instanceKeyPair.publicKey.export({ format: 'jwk' }),
            // },
          })
            .setProtectedHeader({
              typ: 'oauth-client-attestation+jwt',
              alg: 'RS256',
            })
            .setSubject('attest_jwt_client_auth')
            .setIssuedAt()
            .setExpirationTime('2h')
            .sign(privateKey),
          new SignJWT({
            cnf: {
              jwk: instanceKeyPair.publicKey.export({ format: 'jwk' }),
            },
          })
            .setProtectedHeader({
              // typ: 'oauth-client-attestation+jwt',
              alg: 'RS256',
            })
            .setSubject('attest_jwt_client_auth')
            .setIssuedAt()
            .setExpirationTime('2h')
            .sign(privateKey),
          new SignJWT({
            cnf: {
              jwk: instanceKeyPair.publicKey.export({ format: 'jwk' }),
            },
          })
            .setProtectedHeader({
              typ: 'foo',
              alg: 'RS256',
            })
            .setSubject('attest_jwt_client_auth')
            .setIssuedAt()
            .setExpirationTime('2h')
            .sign(privateKey),
        ])) {
          await fixture12.agent.post(route)
            .set('OAuth-Client-Attestation', attestation)
            .set('OAuth-Client-Attestation-PoP', await fixture12.signPop())
            .send({
              grant_type: 'foo',
            })
            .type('form')
            .expect(tokenAuthRejected);
        }
      });
    });

    describe('oauth-client-attestation-pop', () => {
      const fixture13 = Object.create(fixture11);

      before(() => {
        fixture13.signAttestation = () => new SignJWT({
          cnf: {
            jwk: instanceKeyPair.publicKey.export({ format: 'jwk' }),
          },
        })
          .setProtectedHeader({
            typ: 'oauth-client-attestation+jwt',
            alg: 'RS256',
          })
          .setSubject('attest_jwt_client_auth')
          .setIssuedAt()
          .setExpirationTime('2h')
          .sign(privateKey);
      }, { timeout: 3000 });

      it('must not be re-used', { timeout: 3000 }, async () => {
        const pop = await new SignJWT({ challenge })
          .setProtectedHeader({
            typ: 'oauth-client-attestation-pop+jwt',
            alg: 'Ed25519',
          })
          .setAudience(fixture13.provider.issuer)
          .setJti(nanoid())
          .setIssuedAt()
          .sign(instanceKeyPair.privateKey);

        await fixture13.agent.post(route)
          .set('OAuth-Client-Attestation', await fixture13.signAttestation())
          .set('OAuth-Client-Attestation-PoP', pop)
          .send({
            grant_type: 'foo',
          })
          .type('form')
          .expect(tokenAuthSucceeded);

        await fixture13.agent.post(route)
          .set('OAuth-Client-Attestation', await fixture13.signAttestation())
          .set('OAuth-Client-Attestation-PoP', pop)
          .send({
            grant_type: 'foo',
          })
          .type('form')
          .expect(tokenAuthRejected);
      });

      for (const [jti, description] of [[123, 'non-string'], ['', 'empty']]) {
        it(`rejects a ${description} jti`, { timeout: 3000 }, async () => {
          const pop = await new SignJWT({ challenge, jti })
            .setProtectedHeader({
              typ: 'oauth-client-attestation-pop+jwt',
              alg: 'Ed25519',
            })
            .setAudience(fixture13.provider.issuer)
            .setIssuedAt()
            .sign(instanceKeyPair.privateKey);

          await fixture13.agent.post(route)
            .set('OAuth-Client-Attestation', await fixture13.signAttestation())
            .set('OAuth-Client-Attestation-PoP', pop)
            .send({
              grant_type: 'foo',
            })
            .type('form')
            .expect(401)
            .expect(tokenAuthRejected);
        });
      }

      describe('challenge handling', async () => {
        const fixture14 = Object.create(fixture13);

        it('requires challenge to be present', { timeout: 3000 }, async () => {
          const pop = await new SignJWT({ challenge: undefined })
            .setProtectedHeader({
              typ: 'oauth-client-attestation-pop+jwt',
              alg: 'Ed25519',
            })
            .setAudience(fixture14.provider.issuer)
            .setJti(nanoid())
            .setIssuedAt()
            .sign(instanceKeyPair.privateKey);

          await fixture14.agent.post(route)
            .set('OAuth-Client-Attestation', await fixture14.signAttestation())
            .set('OAuth-Client-Attestation-PoP', pop)
            .send({
              grant_type: 'foo',
            })
            .type('form')
            .expect(400)
            .expect('OAuth-Client-Attestation-Challenge', /^[A-Za-z0-9_-]+$/)
            .expect({ error: 'use_attestation_challenge' });
        });

        it('requires a valid challenge to be present', { timeout: 3000 }, async () => {
          const pop = await new SignJWT({ challenge: 'invalid' })
            .setProtectedHeader({
              typ: 'oauth-client-attestation-pop+jwt',
              alg: 'Ed25519',
            })
            .setAudience(fixture14.provider.issuer)
            .setJti(nanoid())
            .setIssuedAt()
            .sign(instanceKeyPair.privateKey);

          await fixture14.agent.post(route)
            .set('OAuth-Client-Attestation', await fixture14.signAttestation())
            .set('OAuth-Client-Attestation-PoP', pop)
            .send({
              grant_type: 'foo',
            })
            .type('form')
            .expect(400)
            .expect('OAuth-Client-Attestation-Challenge', /^[A-Za-z0-9_-]+$/)
            .expect({ error: 'use_attestation_challenge' });
        });
      });

      it('checks all required properties and their values', { timeout: 3000 }, async () => {
        for (const pop of await Promise.all([
          new SignJWT({ challenge })
            .setProtectedHeader({
              typ: 'oauth-client-attestation-pop+jwt',
              alg: 'Ed25519',
            })
            .setAudience(fixture13.provider.issuer)
            // .setJti(nanoid())
            .setIssuedAt()
            .sign(instanceKeyPair.privateKey),
          new SignJWT({ challenge })
            .setProtectedHeader({
              typ: 'oauth-client-attestation-pop+jwt',
              alg: 'Ed25519',
            })
            // .setAudience(this.provider.issuer)
            .setJti(nanoid())
            .setIssuedAt()
            .sign(instanceKeyPair.privateKey),
          new SignJWT({ challenge })
            .setProtectedHeader({
              typ: 'oauth-client-attestation-pop+jwt',
              alg: 'Ed25519',
            })
            .setAudience([fixture13.provider.issuer])
            .setJti(nanoid())
            .setIssuedAt()
            .sign(instanceKeyPair.privateKey),
          new SignJWT({ challenge })
            .setProtectedHeader({
              typ: 'oauth-client-attestation-pop+jwt',
              alg: 'Ed25519',
            })
            .setAudience('foo')
            .setJti(nanoid())
            .setIssuedAt()
            .sign(instanceKeyPair.privateKey),
          new SignJWT({ challenge })
            .setProtectedHeader({
              // typ: 'oauth-client-attestation-pop+jwt',
              alg: 'Ed25519',
            })
            .setAudience(fixture13.provider.issuer)
            .setJti(nanoid())
            .setIssuedAt()
            .sign(instanceKeyPair.privateKey),
          new SignJWT({ challenge })
            .setProtectedHeader({
              typ: 'foo',
              alg: 'Ed25519',
            })
            .setAudience(fixture13.provider.issuer)
            .setJti(nanoid())
            .setIssuedAt()
            .sign(instanceKeyPair.privateKey),
          new SignJWT({ challenge })
            .setProtectedHeader({
              typ: 'oauth-client-attestation-pop+jwt',
              alg: 'Ed25519',
            })
            .setAudience(fixture13.provider.issuer)
            .setJti(nanoid())
            // .setIssuedAt()
            .sign(instanceKeyPair.privateKey),
        ])) {
          await fixture13.agent.post(route)
            .set('OAuth-Client-Attestation', await fixture13.signAttestation())
            .set('OAuth-Client-Attestation-PoP', pop)
            .send({
              grant_type: 'foo',
            })
            .type('form')
            .expect(tokenAuthRejected);
        }
      });
    });
  });

  describe('attest_jwt_client_auth_dpop auth', () => {
    const fixture15 = Object.create(fixture);

    const instanceKeyPair = generateKeyPairSync('ed25519');
    let nonce;

    before(async () => {
      fixture15.origRequireNonce = i(fixture15.provider).features.dPoP.requireNonce;
      i(fixture15.provider).features.dPoP.requireNonce = () => true;

      const response = await fixture15.agent.post('/challenge')
        .expect(200)
        .expect('DPoP-Nonce', /^[\w-]{43}$/);
      nonce = response.headers['dpop-nonce'];
    }, { timeout: 3000 });

    after(() => {
      i(fixture15.provider).features.dPoP.requireNonce = fixture15.origRequireNonce;
    }, { timeout: 3000 });

    it('requires a DPoP nonce even when requireNonce is false', { timeout: 3000 }, async () => {
      const { dPoP } = i(fixture15.provider).features;
      const original = dPoP.requireNonce;
      dPoP.requireNonce = () => false;
      try {
        await fixture15.agent.post('/challenge')
          .expect(200)
          .expect('DPoP-Nonce', /^[\w-]{43}$/);

        await fixture15.agent.post(route)
          .set('OAuth-Client-Attestation', await signAttestation('attest_jwt_client_auth_dpop', instanceKeyPair))
          .set('DPoP', await signDpop(fixture15, instanceKeyPair))
          .send({ grant_type: 'foo' })
          .type('form')
          .expect(400)
          .expect(noW3A)
          .expect('DPoP-Nonce', /^[\w-]{43}$/)
          .expect({
            error: 'use_dpop_nonce',
            error_description: 'nonce is required in the DPoP proof',
          })
          .expect(({ headers }) => {
            assert.ok(!('oauth-client-attestation-challenge' in Object(headers)));
          });
      } finally {
        dPoP.requireNonce = original;
      }
    });

    it('accepts the auth using the DPoP nonce from the challenge endpoint', { timeout: 3000 }, async () => {
      const spy = sinon.spy();
      fixture15.provider.once('grant.success', spy);

      await fixture15.agent.post(route)
        .set('OAuth-Client-Attestation', await signAttestation('attest_jwt_client_auth_dpop', instanceKeyPair))
        .set('DPoP', await signDpop(fixture15, instanceKeyPair, nonce))
        .send({ grant_type: 'foo' })
        .type('form')
        .expect(200)
        .expect(tokenAuthSucceeded)
        .expect(({ headers }) => {
          assert.ok(!('oauth-client-attestation-challenge' in Object(headers)));
          assert.equal(spy.calledOnce, true);
          ((actual) => { assert.ok("method" in Object(actual)); assert.equal(actual.method, 'dpop_combined'); assert.ok("signal" in Object(actual)); assert.equal(actual.signal, false); })(spy.firstCall.args[0].oidc.clientAttestation);
        });
    });

    it('compares public keys independently of optional JWK members', { timeout: 3000 }, async () => {
      const jwk = {
        ...instanceKeyPair.publicKey.export({ format: 'jwk' }),
        kid: 'attested-instance',
      };

      await fixture15.agent.post(route)
        .set('OAuth-Client-Attestation', await signAttestation('attest_jwt_client_auth_dpop', instanceKeyPair, jwk))
        .set('DPoP', await signDpop(fixture15, instanceKeyPair, nonce))
        .send({ grant_type: 'foo' })
        .type('form')
        .expect(200)
        .expect(tokenAuthSucceeded);
    });

    for (const [value, description] of [[undefined, 'missing'], ['invalid', 'invalid']]) {
      it(`rejects a ${description} DPoP nonce with use_dpop_nonce`, { timeout: 3000 }, async () => {
        await fixture15.agent.post(route)
          .set('OAuth-Client-Attestation', await signAttestation('attest_jwt_client_auth_dpop', instanceKeyPair))
          .set('DPoP', await signDpop(fixture15, instanceKeyPair, value))
          .send({ grant_type: 'foo' })
          .type('form')
          .expect(400)
          .expect(noW3A)
          .expect('DPoP-Nonce', /^[\w-]{43}$/)
          .expect({
            error: 'use_dpop_nonce',
            error_description: value ? 'invalid nonce in DPoP proof' : 'nonce is required in the DPoP proof',
          })
          .expect(({ headers }) => {
            assert.ok(!('oauth-client-attestation-challenge' in Object(headers)));
          });
      });
    }

    it('rejects an invalid DPoP proof with invalid_dpop_proof', { timeout: 3000 }, async () => {
      await fixture15.agent.post(route)
        .set('OAuth-Client-Attestation', await signAttestation('attest_jwt_client_auth_dpop', instanceKeyPair))
        .set('DPoP', 'invalid')
        .send({ grant_type: 'foo' })
        .type('form')
        .expect(400)
        .expect(noW3A)
        .expect({
          error: 'invalid_dpop_proof',
          error_description: 'invalid DPoP key binding',
        });
    });

    it('rejects a DPoP key that differs from the attestation key', { timeout: 3000 }, async () => {
      const otherKeyPair = generateKeyPairSync('ed25519');

      await fixture15.agent.post(route)
        .set('OAuth-Client-Attestation', await signAttestation('attest_jwt_client_auth_dpop', instanceKeyPair))
        .set('DPoP', await signDpop(fixture15, otherKeyPair, nonce))
        .send({ grant_type: 'foo' })
        .type('form')
        .expect(401)
        .expect(tokenAuthRejected);
    });

    it('rejects a replayed DPoP proof', { timeout: 3000 }, async () => {
      const attestation = await signAttestation('attest_jwt_client_auth_dpop', instanceKeyPair);
      const dpop = await signDpop(fixture15, instanceKeyPair, nonce);

      await fixture15.agent.post(route)
        .set('OAuth-Client-Attestation', attestation)
        .set('DPoP', dpop)
        .send({ grant_type: 'foo' })
        .type('form')
        .expect(200)
        .expect(tokenAuthSucceeded);

      await fixture15.agent.post(route)
        .set('OAuth-Client-Attestation', attestation)
        .set('DPoP', dpop)
        .send({ grant_type: 'foo' })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_dpop_proof',
          error_description: 'DPoP proof JWT Replay detected',
        });
    });

    it('rejects the auth without a DPoP proof', { timeout: 3000 }, async () => {
      await fixture15.agent.post(route)
        .set('OAuth-Client-Attestation', await signAttestation('attest_jwt_client_auth_dpop', instanceKeyPair))
        .send({ grant_type: 'foo' })
        .type('form')
        .expect(401)
        .expect(tokenAuthRejected);
    });

    it('rejects combined mode when DPoP is disabled', { timeout: 3000 }, async () => {
      const { dPoP } = i(fixture15.provider).features;
      dPoP.enabled = false;
      try {
        await fixture15.agent.post(route)
          .set('OAuth-Client-Attestation', await signAttestation('attest_jwt_client_auth_dpop', instanceKeyPair))
          .set('DPoP', await signDpop(fixture15, instanceKeyPair, nonce))
          .send({ grant_type: 'foo' })
          .type('form')
          .expect(401)
          .expect(tokenAuthRejected);
      } finally {
        dPoP.enabled = true;
      }
    });

    it('rejects the auth with an attestation PoP JWT', { timeout: 3000 }, async () => {
      const { body: { attestation_challenge: challenge } } = await fixture15.agent.post('/challenge');

      await fixture15.agent.post(route)
        .set('OAuth-Client-Attestation', await signAttestation('attest_jwt_client_auth_dpop', instanceKeyPair))
        .set('OAuth-Client-Attestation-PoP', await signAttestationPop(fixture15.provider, instanceKeyPair, challenge))
        .set('DPoP', await signDpop(fixture15, instanceKeyPair, nonce))
        .send({ grant_type: 'foo' })
        .type('form')
        .expect(401)
        .expect(tokenAuthRejected);
    });

    it('rejects combined mode for a client registered with attest_jwt_client_auth', { timeout: 3000 }, async () => {
      await fixture15.agent.post(route)
        .set('OAuth-Client-Attestation', await signAttestation('attest_jwt_client_auth', instanceKeyPair))
        .set('DPoP', await signDpop(fixture15, instanceKeyPair, nonce))
        .send({ grant_type: 'foo' })
        .type('form')
        .expect(401)
        .expect(tokenAuthRejected);
    });

    it('accepts attest_jwt_client_auth alongside independent DPoP with a different key', { timeout: 3000 }, async () => {
      const { body: { attestation_challenge: challenge } } = await fixture15.agent.post('/challenge');
      const otherKeyPair = generateKeyPairSync('ed25519');
      const spy = sinon.spy();
      fixture15.provider.once('grant.success', spy);

      const { body } = await fixture15.agent.post(route)
        .set('OAuth-Client-Attestation', await signAttestation('attest_jwt_client_auth', instanceKeyPair))
        .set('OAuth-Client-Attestation-PoP', await signAttestationPop(fixture15.provider, instanceKeyPair, challenge))
        .set('DPoP', await signDpop(fixture15, otherKeyPair, nonce))
        .send({ grant_type: 'client_credentials' })
        .type('form')
        .expect(200)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          ((actual) => { assert.ok("method" in Object(actual)); assert.equal(actual.method, 'attestation_pop_jwt'); assert.ok("signal" in Object(actual)); assert.equal(actual.signal, false); })(spy.firstCall.args[0].oidc.clientAttestation);
        });

      ((actual) => { assert.ok('token_type' in Object(actual)); assert.equal(actual.token_type, 'DPoP'); })(body);
      const token = await fixture15.provider.ClientCredentials.find(body.access_token);
      ((actual, expected0) => { assert.ok('jkt' in Object(actual)); assert.equal(actual.jkt, expected0); })(token, await calculateJwkThumbprint(otherKeyPair.publicKey.export({ format: 'jwk' })));

      await fixture15.agent.post(route)
        .set('OAuth-Client-Attestation', await signAttestation('attest_jwt_client_auth', instanceKeyPair))
        .set('OAuth-Client-Attestation-PoP', await signAttestationPop(fixture15.provider, instanceKeyPair, challenge))
        .set('DPoP', 'invalid')
        .send({ grant_type: 'client_credentials' })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_dpop_proof',
          error_description: 'invalid DPoP key binding',
        });
    });

    it('authenticates introspection and exposes DPoP nonce errors through CORS', { timeout: 3000 }, async () => {
      const { configuration } = i(fixture15.provider);
      const original = configuration.clientBasedCORS;
      configuration.clientBasedCORS = () => true;
      try {
        await fixture15.agent.post('/token/introspection')
          .set('Origin', 'https://rp.example.com')
          .set('OAuth-Client-Attestation', await signAttestation('attest_jwt_client_auth_dpop', instanceKeyPair))
          .set('DPoP', await signDpop(fixture15, instanceKeyPair, nonce, '/token/introspection'))
          .send({ token: 'not-found' })
          .type('form')
          .expect(200)
          .expect('Access-Control-Allow-Origin', 'https://rp.example.com')
          .expect('Access-Control-Expose-Headers', /DPoP-Nonce/)
          .expect(introspectionAuthSucceeded);

        await fixture15.agent.post('/token/introspection')
          .set('Origin', 'https://rp.example.com')
          .set('OAuth-Client-Attestation', await signAttestation('attest_jwt_client_auth_dpop', instanceKeyPair))
          .set('DPoP', await signDpop(fixture15, instanceKeyPair, undefined, '/token/introspection'))
          .send({ token: 'not-found' })
          .type('form')
          .expect(400)
          .expect('Access-Control-Allow-Origin', 'https://rp.example.com')
          .expect('Access-Control-Expose-Headers', /DPoP-Nonce/)
          .expect('DPoP-Nonce', /^[\w-]{43}$/)
          .expect({
            error: 'use_dpop_nonce',
            error_description: 'nonce is required in the DPoP proof',
          });
      } finally {
        configuration.clientBasedCORS = original;
      }
    });

    it('rejects a token endpoint DPoP proof at introspection', { timeout: 3000 }, async () => {
      await fixture15.agent.post('/token/introspection')
        .set('OAuth-Client-Attestation', await signAttestation('attest_jwt_client_auth_dpop', instanceKeyPair))
        .set('DPoP', await signDpop(fixture15, instanceKeyPair, nonce))
        .send({ token: 'not-found' })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_dpop_proof',
          error_description: 'DPoP proof htu mismatch',
        });
    });
  });

  describe('tls_client_auth auth', () => {
    const fixture16 = Object.create(fixture);

    it('accepts the auth', { timeout: 3000 }, () => fixture16.agent.post(route)
        .set('x-ssl-client-cert', rsacrt.raw.toString('base64'))
        .set('x-ssl-client-verify', 'SUCCESS')
        .set('x-ssl-client-san-dns', 'rp.example.com')
        .send({
          client_id: 'client-pki-mtls',
          grant_type: 'foo',
        })
        .type('form')
        .expect(200)
        .expect(tokenAuthSucceeded));

    it('fails the auth when getCertificate() does not return a cert', { timeout: 3000 }, () => fixture16.agent.post(route)
        .send({
          client_id: 'client-pki-mtls',
          grant_type: 'foo',
        })
        .type('form')
        .expect(tokenAuthRejected));

    it('fails the auth when certificateAuthorized() fails', { timeout: 3000 }, () => fixture16.agent.post(route)
        .set('x-ssl-client-cert', rsacrt.raw.toString('base64'))
        .set('x-ssl-client-verify', 'FAILED: self signed certificate')
        .set('x-ssl-client-san-dns', 'rp.example.com')
        .send({
          client_id: 'client-pki-mtls',
          grant_type: 'foo',
        })
        .type('form')
        .expect(tokenAuthRejected));

    it('fails the auth when certificateSubjectMatches() return false', { timeout: 3000 }, () => fixture16.agent.post(route)
        .set('x-ssl-client-cert', rsacrt.raw.toString('base64'))
        .set('x-ssl-client-verify', 'SUCCESS')
        .set('x-ssl-client-san-dns', 'foobarbaz')
        .send({
          client_id: 'client-pki-mtls',
          grant_type: 'foo',
        })
        .type('form')
        .expect(tokenAuthRejected));
  });

  describe('self_signed_tls_client_auth auth', () => {
    const fixture17 = Object.create(fixture);

    it('accepts the auth [1/2]', { timeout: 3000 }, () => fixture17.agent.post(route)
        .set('x-ssl-client-cert', rsacrt.raw.toString('base64'))
        .send({
          client_id: 'client-self-signed-mtls',
          grant_type: 'foo',
        })
        .type('form')
        .expect(200)
        .expect(tokenAuthSucceeded));

    it('accepts the auth [2/2]', { timeout: 3000 }, () => fixture17.agent.post(route)
        .set('x-ssl-client-cert', eccrt.raw.toString('base64'))
        .send({
          client_id: 'client-self-signed-mtls',
          grant_type: 'foo',
        })
        .type('form')
        .expect(200)
        .expect(tokenAuthSucceeded));

    it('fails the auth when x-ssl-client-cert is not passed by the proxy', { timeout: 3000 }, () => fixture17.agent.post(route)
        .send({
          client_id: 'client-self-signed-mtls',
          grant_type: 'foo',
        })
        .type('form')
        .expect(tokenAuthRejected));

    it('fails the auth when x-ssl-client-cert does not match the registered ones', { timeout: 3000 }, () => fixture17.agent.post(route)
        .set('x-ssl-client-cert', eccrt.raw.toString('base64'))
        .send({
          client_id: 'client-self-signed-mtls-rsa',
          grant_type: 'foo',
        })
        .type('form')
        .expect(tokenAuthRejected));

    it('handles rotation of stale jwks', { timeout: 3000 }, () => {
      mock('https://client.example.com')
        .intercept({
          path: '/jwks',
        })
        .reply(200, JSON.stringify(mtlsKeys));

      return fixture17.agent.post(route)
        .set('x-ssl-client-cert', rsacrt.raw.toString('base64'))
        .send({
          client_id: 'client-self-signed-mtls-jwks_uri',
          grant_type: 'foo',
        })
        .type('form')
        .expect(200)
        .expect(tokenAuthSucceeded);
    });
  });
});
