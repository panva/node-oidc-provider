import { randomUUID } from 'node:crypto';

import { expect } from 'chai';
import {
  exportJWK,
  generateKeyPair,
  SignJWT,
} from 'jose';

import bootstrap from '../test_helper.js';

import {
  API,
  SECOND_API,
} from './custom_grants.config.js';
import * as clientCredentials from './grants/client_credentials.js';
import * as jwtBearer from './grants/jwt_bearer.js';
import * as saml2Bearer from './grants/saml2_bearer.js';
import * as tokenExchange from './grants/token_exchange.js';

const JWT_ISSUER = 'https://jwt-idp.example.com';
const SAML_ISSUER = 'https://saml-idp.example.com';
const ARBITRARY_TOKEN_TYPE = 'urn:example:params:oauth:token-type:arbitrary';
const INVALID_OUTPUT_TOKEN_TYPE = 'urn:example:params:oauth:token-type:invalid-output';
const PAYMENT = [{ type: 'payment', amount: 10, locations: [API] }];
const MULTI_LOCATION_PAYMENT = [{
  type: 'payment',
  amount: 10,
  locations: [API, SECOND_API],
}];
const BROAD_PAYMENTS = [
  ...PAYMENT,
  { type: 'payment', amount: 20, locations: [API] },
];
const PAYMENT_FIELDS = new Set(['amount', 'locations', 'type']);

function normalizePaymentAuthorizationDetail(detail) {
  if (
    detail === null
    || typeof detail !== 'object'
    || Array.isArray(detail)
    || Object.keys(detail).some((field) => !PAYMENT_FIELDS.has(field))
    || detail.type !== 'payment'
    || !Number.isFinite(detail.amount)
    || detail.amount <= 0
    || !Array.isArray(detail.locations)
    || detail.locations.length === 0
    || detail.locations.some((location) => typeof location !== 'string' || !location)
  ) {
    throw new TypeError('invalid payment authorization details');
  }

  return detail;
}

// RFC 9396 leaves comparison to each authorization-details type. For this
// fixture, a payment amount identifies a specific payment and locations are
// additive rights that can be narrowed to a subset.
async function paymentAuthorizationDetailsPolicy(_ctx, { allowed, mode, requested }) {
  const permissions = allowed.map(normalizePaymentAuthorizationDetail);
  const projected = requested
    .map(normalizePaymentAuthorizationDetail)
    .filter((detail) => permissions.some((permission) => (
      permission.amount === detail.amount
      && detail.locations.every((location) => permission.locations.includes(location))
    )));

  if (mode === 'subset' && projected.length !== requested.length) {
    throw new Error('requested payment authorization details exceed the source authorization');
  }

  return projected.length ? projected : undefined;
}

function now() {
  return Math.floor(Date.now() / 1000);
}

async function signAssertion(privateKey, {
  audience,
  authorizationDetails = PAYMENT,
  issuer = JWT_ISSUER,
  jti = randomUUID(),
  resource = API,
  scope = 'api:read',
  subject = 'external-user',
  expiresIn = 120,
} = {}) {
  return new SignJWT({
    authorization_details: authorizationDetails,
    resource,
    scope,
  })
    .setProtectedHeader({ alg: 'ES256' })
    .setIssuer(issuer)
    .setSubject(subject)
    .setAudience(audience)
    .setJti(jti)
    .setIssuedAt()
    .setExpirationTime(now() + expiresIn)
    .sign(privateKey);
}

async function signClaims(privateKey, claims, alg = 'ES256') {
  return new SignJWT({
    authorization_details: PAYMENT,
    resource: API,
    scope: 'api:read',
    ...claims,
  })
    .setProtectedHeader({ alg })
    .sign(privateKey);
}

function encodeSamlFixture(overrides = {}) {
  return Buffer.from(JSON.stringify({
    assertionId: randomUUID(),
    audiences: [],
    authorizationDetails: PAYMENT,
    clientId: 'client',
    expiresAt: now() + 120,
    issuer: SAML_ISSUER,
    resource: API,
    scope: 'api:read',
    signature: 'valid',
    subject: 'saml-user',
    ...overrides,
  })).toString('base64url');
}

async function verifySamlFixture(_ctx, encoded) {
  const assertion = JSON.parse(Buffer.from(encoded, 'base64url').toString());
  if (assertion.signature !== 'valid') {
    throw new Error('XML signature validation failed');
  }
  delete assertion.signature;
  return assertion;
}

async function issueSource(provider, client, {
  accountId = 'source-user',
  rar,
  resource = API,
  scope = 'api:read',
} = {}) {
  const grant = new provider.Grant({ accountId, clientId: client.clientId });
  grant.addResourceScope(resource, scope);
  for (const detail of rar ?? []) {
    grant.addRar(detail);
  }
  const grantId = await grant.save();
  const token = new provider.AccessToken({
    accountId,
    client,
    grantId,
    gty: 'authorization_code',
    scope,
  });
  token.rar = rar;
  token.setAudience(resource);
  return { grant, token, value: await token.save() };
}

async function dpopProof(provider, keyPair, htu = `${provider.issuer}/token`) {
  return new SignJWT({
    htm: 'POST',
    htu,
  })
    .setProtectedHeader({
      alg: 'ES256',
      jwk: await exportJWK(keyPair.publicKey),
      typ: 'dpop+jwt',
    })
    .setJti(randomUUID())
    .setIssuedAt()
    .sign(keyPair.privateKey);
}

describe('consumer-style custom grant implementations', () => {
  before(bootstrap(import.meta.url));

  before(async function () {
    this.jwtKeyPair = await generateKeyPair('ES256');
    this.otherKeyPair = await generateKeyPair('ES256');
    this.tokenExchangeAuthorizations = [];
    this.tokenUrl = new URL(this.suitePath('/token'), this.provider.issuer).href;

    clientCredentials.register(this.provider);
    tokenExchange.register(this.provider, {
      authorizationDetailsPolicy: paymentAuthorizationDetailsPolicy,
      authorize: async (_ctx, input) => {
        this.tokenExchangeAuthorizations.push(input);
        return {
          ...input,
          authorizationDetails: input.authorizationDetails?.slice(0, 1),
        };
      },
      async issueToken(_ctx, exchange) {
        if (exchange.requestedTokenType === INVALID_OUTPUT_TOKEN_TYPE) {
          return { accessToken: 'invalid-output', tokenType: 'N_A' };
        }
        if (exchange.requestedTokenType !== ARBITRARY_TOKEN_TYPE) {
          return undefined;
        }

        return {
          accessToken: 'arbitrary-security-token',
          expiresIn: 60,
          issuedTokenType: ARBITRARY_TOKEN_TYPE,
          parameters: { example_parameter: 'example-value' },
          tokenType: 'N_A',
        };
      },
    });
    jwtBearer.register(this.provider, {
      authorizationDetailsPolicy: paymentAuthorizationDetailsPolicy,
      authorize: async (_ctx, input) => ({
        ...input,
        authorizationDetails: input.authorizationDetails?.slice(0, 1),
      }),
      mapSubject: (_ctx, payload) => `mapped:${payload.sub}`,
      rejectReplay: true,
      trustedIssuers: new Map([[
        JWT_ISSUER,
        { algorithms: ['ES256'], key: this.jwtKeyPair.publicKey },
      ]]),
    });
    saml2Bearer.register(this.provider, {
      authorizationDetailsPolicy: paymentAuthorizationDetailsPolicy,
      authorize: async (_ctx, input) => ({
        ...input,
        authorizationDetails: input.authorizationDetails?.slice(0, 1),
      }),
      trustedIssuers: new Set([SAML_ISSUER]),
      verifyAssertion: verifySamlFixture,
    });

    this.client = await this.provider.Client.find('client');
    this.client.grantTypes.push(
      clientCredentials.grantType,
      tokenExchange.grantType,
      jwtBearer.grantType,
      saml2Bearer.grantType,
    );
  });

  describe('client_credentials override', () => {
    it('uses resource, RAR, sender-constraint, persistence, and response stages', async function () {
      const keyPair = await generateKeyPair('ES256', { extractable: true });
      let success;
      this.provider.once('grant.success', (ctx) => {
        success = ctx;
      });
      const response = await this.agent.post('/token')
        .auth('client', 'secret')
        .set('DPoP', await dpopProof(this.provider, keyPair, this.tokenUrl))
        .send({
          authorization_details: JSON.stringify(PAYMENT),
          grant_type: clientCredentials.grantType,
          resource: API,
          scope: 'api:read',
        })
        .type('form')
        .expect(200);

      expect(response.body).to.include({ scope: 'api:read', token_type: 'DPoP' });
      expect(response.body.authorization_details).to.deep.equal(PAYMENT);
      const stored = await this.provider.ClientCredentials.find(response.body.access_token);
      expect(stored).to.include({ aud: API, scope: 'api:read' });
      expect(stored).to.have.property('jkt');
      expect(success.oidc.entities).to.have.keys('Client', 'ClientCredentials');
    });

    it('rejects client-disallowed static scope', function () {
      return this.agent.post('/token')
        .auth('client', 'secret')
        .send({
          grant_type: clientCredentials.grantType,
          resource: API,
          scope: 'api:write',
        })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_scope',
          error_description: 'requested scope is not allowed',
          scope: 'api:write',
        });
    });

    it('rejects multiple provider-native token targets', function () {
      return this.agent.post('/token')
        .auth('client', 'secret')
        .send({
          grant_type: clientCredentials.grantType,
          resource: [API, SECOND_API],
          scope: 'api:read',
        })
        .type('form')
        .expect(400)
        .expect((response) => {
          expect(response.body).to.include({ error: 'invalid_target' });
        });
    });
  });

  describe('RFC 8693 token exchange', () => {
    it('issues a provider access token without consuming its inputs', async function () {
      const subject = await issueSource(this.provider, this.client, { rar: PAYMENT });
      const actor = await issueSource(this.provider, this.client, { accountId: 'actor-user' });
      let grantSuccesses = 0;
      let grantContext;
      const listener = (ctx) => {
        grantSuccesses += 1;
        grantContext = ctx;
      };
      this.provider.on('grant.success', listener);

      const response = await this.agent.post('/token')
        .auth('client', 'secret')
        .send({
          actor_token: actor.value,
          actor_token_type: tokenExchange.accessTokenType,
          audience: API,
          authorization_details: JSON.stringify(PAYMENT),
          grant_type: tokenExchange.grantType,
          requested_token_type: tokenExchange.accessTokenType,
          resource: API,
          scope: 'api:read',
          subject_token: subject.value,
          subject_token_type: tokenExchange.accessTokenType,
        })
        .type('form')
        .expect(200);
      this.provider.off('grant.success', listener);

      expect(response.body).to.include({
        issued_token_type: tokenExchange.accessTokenType,
        scope: 'api:read',
        token_type: 'Bearer',
      });
      expect(response.body.authorization_details).to.deep.equal(PAYMENT);

      const output = await this.provider.AccessToken.find(response.body.access_token);
      expect(output).to.include({ accountId: 'source-user', aud: API });
      expect(output.extra.act).to.deep.equal({ sub: 'actor-user' });
      expect((await this.provider.AccessToken.find(subject.value)).consumed).to.be.undefined;
      expect((await this.provider.AccessToken.find(actor.value)).consumed).to.be.undefined;
      expect(this.tokenExchangeAuthorizations.at(-1)).to.include.keys(
        'actorToken',
        'audiences',
        'resourceServers',
        'subjectToken',
      );
      expect(grantSuccesses).to.equal(1);
      expect(grantContext.oidc.entities).to.have.keys(
        'AccessToken',
        'Account',
        'Client',
        'Grant',
      );
    });

    it('uses payment-type semantics to narrow locations independently of JSON shape', async function () {
      const subject = await issueSource(this.provider, this.client, {
        rar: MULTI_LOCATION_PAYMENT,
      });
      const requested = [{ locations: [API], amount: 10, type: 'payment' }];
      const response = await this.agent.post('/token')
        .auth('client', 'secret')
        .send({
          authorization_details: JSON.stringify(requested),
          grant_type: tokenExchange.grantType,
          resource: API,
          subject_token: subject.value,
          subject_token_type: tokenExchange.accessTokenType,
        })
        .type('form')
        .expect(200);

      expect(response.body.authorization_details).to.deep.equal(PAYMENT);
    });

    it('returns arbitrary security tokens through the RFC 8693 response shape', async function () {
      const subject = await issueSource(this.provider, this.client);
      const response = await this.agent.post('/token')
        .auth('client', 'secret')
        .send({
          grant_type: tokenExchange.grantType,
          requested_token_type: ARBITRARY_TOKEN_TYPE,
          scope: 'api:read',
          subject_token: subject.value,
          subject_token_type: tokenExchange.accessTokenType,
        })
        .type('form')
        .expect(200);

      expect(response.body).to.deep.equal({
        access_token: 'arbitrary-security-token',
        example_parameter: 'example-value',
        expires_in: 60,
        issued_token_type: ARBITRARY_TOKEN_TYPE,
        scope: 'api:read',
        token_type: 'N_A',
      });
    });

    it('requires arbitrary-token issuers to return issued_token_type', async function () {
      const subject = await issueSource(this.provider, this.client);
      const proof = await dpopProof(this.provider, this.jwtKeyPair, this.tokenUrl);
      await this.agent.post('/token')
        .auth('client', 'secret')
        .set('DPoP', proof)
        .send({
          grant_type: tokenExchange.grantType,
          requested_token_type: INVALID_OUTPUT_TOKEN_TYPE,
          subject_token: subject.value,
          subject_token_type: tokenExchange.accessTokenType,
        })
        .type('form')
        .expect(500)
        .expect((response) => {
          expect(response.body).to.include({ error: 'server_error' });
        });

      await this.agent.post('/token')
        .auth('client', 'secret')
        .set('DPoP', proof)
        .send({
          grant_type: tokenExchange.grantType,
          requested_token_type: ARBITRARY_TOKEN_TYPE,
          subject_token: subject.value,
          subject_token_type: tokenExchange.accessTokenType,
        })
        .type('form')
        .expect(200);
    });

    it('keeps authorization-policy RAR narrowing authoritative', async function () {
      const subject = await issueSource(this.provider, this.client, { rar: BROAD_PAYMENTS });
      const response = await this.agent.post('/token')
        .auth('client', 'secret')
        .send({
          authorization_details: JSON.stringify(BROAD_PAYMENTS),
          grant_type: tokenExchange.grantType,
          resource: API,
          subject_token: subject.value,
          subject_token_type: tokenExchange.accessTokenType,
        })
        .type('form')
        .expect(200);

      expect(response.body.authorization_details).to.deep.equal(PAYMENT);
      const stored = await this.provider.AccessToken.find(response.body.access_token);
      expect(stored.rar).to.deep.equal(PAYMENT);
    });

    it('does not consume DPoP replay state when arbitrary-token issuance is declined', async function () {
      const subject = await issueSource(this.provider, this.client);
      const proof = await dpopProof(this.provider, this.jwtKeyPair, this.tokenUrl);

      await this.agent.post('/token')
        .auth('client', 'secret')
        .set('DPoP', proof)
        .send({
          grant_type: tokenExchange.grantType,
          requested_token_type: 'urn:example:unsupported',
          subject_token: subject.value,
          subject_token_type: tokenExchange.accessTokenType,
        })
        .type('form')
        .expect(400)
        .expect((response) => {
          expect(response.body).to.include({ error: 'invalid_request' });
        });

      await this.agent.post('/token')
        .auth('client', 'secret')
        .set('DPoP', proof)
        .send({
          grant_type: tokenExchange.grantType,
          requested_token_type: ARBITRARY_TOKEN_TYPE,
          subject_token: subject.value,
          subject_token_type: tokenExchange.accessTokenType,
        })
        .type('form')
        .expect(200);
    });

    it('sanitizes an invalid subject token grant as invalid_request', async function () {
      const subject = await issueSource(this.provider, this.client);
      await subject.grant.destroy();

      return this.agent.post('/token')
        .auth('client', 'secret')
        .send({
          grant_type: tokenExchange.grantType,
          subject_token: subject.value,
          subject_token_type: tokenExchange.accessTokenType,
        })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_request',
          error_description: 'subject token is invalid',
        });
    });

    it('enforces the conditional actor token pair', async function () {
      const subject = await issueSource(this.provider, this.client);
      return this.agent.post('/token')
        .auth('client', 'secret')
        .send({
          actor_token: subject.value,
          grant_type: tokenExchange.grantType,
          subject_token: subject.value,
          subject_token_type: tokenExchange.accessTokenType,
        })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_request',
          error_description: 'actor_token_type must be provided with actor_token',
        });
    });

    it('validates the actor token Grant before using its actor identity', async function () {
      const subject = await issueSource(this.provider, this.client);
      const actor = await issueSource(this.provider, this.client, { accountId: 'actor-user' });
      await actor.grant.destroy();

      await this.agent.post('/token')
        .auth('client', 'secret')
        .send({
          actor_token: actor.value,
          actor_token_type: tokenExchange.accessTokenType,
          grant_type: tokenExchange.grantType,
          subject_token: subject.value,
          subject_token_type: tokenExchange.accessTokenType,
        })
        .type('form')
        .expect(400)
        .expect((response) => {
          expect(response.body).to.include({ error: 'invalid_request' });
        });
    });

    it('rejects missing token pairs and actor type without actor', async function () {
      const subject = await issueSource(this.provider, this.client);
      const cases = [
        {
          body: { subject_token_type: tokenExchange.accessTokenType },
          description: 'subject_token must be provided',
        },
        {
          body: { subject_token: subject.value },
          description: 'subject_token_type must be provided',
        },
        {
          body: {
            actor_token_type: tokenExchange.accessTokenType,
            subject_token: subject.value,
            subject_token_type: tokenExchange.accessTokenType,
          },
          description: 'actor_token_type must not be provided without actor_token',
        },
      ];

      for (const { body, description } of cases) {
        await this.agent.post('/token')
          .auth('client', 'secret')
          .send({ grant_type: tokenExchange.grantType, ...body })
          .type('form')
          .expect(400)
          .expect({ error: 'invalid_request', error_description: description });
      }
    });

    it('rejects unsupported inputs and unrepresentable target combinations', async function () {
      const subject = await issueSource(this.provider, this.client);

      await this.agent.post('/token')
        .auth('client', 'secret')
        .send({
          grant_type: tokenExchange.grantType,
          subject_token: subject.value,
          subject_token_type: 'urn:example:unsupported',
        })
        .type('form')
        .expect(400)
        .expect((response) => {
          expect(response.body).to.include({ error: 'invalid_request' });
        });

      await this.agent.post('/token')
        .auth('client', 'secret')
        .send({
          grant_type: tokenExchange.grantType,
          resource: [API, SECOND_API],
          subject_token: subject.value,
          subject_token_type: tokenExchange.accessTokenType,
        })
        .type('form')
        .expect(400)
        .expect((response) => {
          expect(response.body).to.include({ error: 'invalid_target' });
        });

      await this.agent.post('/token')
        .auth('client', 'secret')
        .send({
          audience: 'logical:other-target',
          grant_type: tokenExchange.grantType,
          resource: API,
          subject_token: subject.value,
          subject_token_type: tokenExchange.accessTokenType,
        })
        .type('form')
        .expect(400)
        .expect((response) => {
          expect(response.body).to.include({ error: 'invalid_target' });
        });
    });

    it('does not permit scope or authorization-details escalation', async function () {
      const subject = await issueSource(this.provider, this.client);
      await this.agent.post('/token')
        .auth('client', 'secret')
        .send({
          grant_type: tokenExchange.grantType,
          scope: 'api:write',
          subject_token: subject.value,
          subject_token_type: tokenExchange.accessTokenType,
        })
        .type('form')
        .expect(400)
        .expect((response) => {
          expect(response.body).to.include({ error: 'invalid_request' });
        });

      await this.agent.post('/token')
        .auth('client', 'secret')
        .send({
          authorization_details: JSON.stringify(BROAD_PAYMENTS),
          grant_type: tokenExchange.grantType,
          resource: API,
          subject_token: subject.value,
          subject_token_type: tokenExchange.accessTokenType,
        })
        .type('form')
        .expect(400)
        .expect((response) => {
          expect(response.body).to.include({ error: 'invalid_request' });
        });
    });
  });

  describe('RFC 7523 JWT bearer', () => {
    it('verifies a signed assertion and caps the access token lifetime', async function () {
      const assertion = await signAssertion(this.jwtKeyPair.privateKey, {
        audience: this.provider.issuer,
        expiresIn: 45,
      });
      const response = await this.agent.post('/token')
        .auth('client', 'secret')
        .send({ assertion, grant_type: jwtBearer.grantType })
        .type('form')
        .expect(200);

      expect(response.body).to.include({
        resource: API,
        scope: 'api:read',
        token_type: 'Bearer',
      });
      expect(response.body.expires_in).to.be.at.most(45);
      expect(response.body.authorization_details).to.deep.equal(PAYMENT);
      const token = await this.provider.AccessToken.find(response.body.access_token);
      expect(token).to.include({ accountId: 'mapped:external-user', aud: API });
    });

    it('does not let the final RAR stage undo injected authorization narrowing', async function () {
      const assertion = await signAssertion(this.jwtKeyPair.privateKey, {
        audience: this.provider.issuer,
        authorizationDetails: BROAD_PAYMENTS,
      });
      const response = await this.agent.post('/token')
        .auth('client', 'secret')
        .send({
          assertion,
          authorization_details: JSON.stringify(BROAD_PAYMENTS),
          grant_type: jwtBearer.grantType,
          resource: API,
        })
        .type('form')
        .expect(200);

      expect(response.body.authorization_details).to.deep.equal(PAYMENT);
      const token = await this.provider.AccessToken.find(response.body.access_token);
      expect(token.rar).to.deep.equal(PAYMENT);
    });

    it('returns a sanitized invalid_grant for a bad signature', async function () {
      const assertion = await signAssertion(this.otherKeyPair.privateKey, {
        audience: this.provider.issuer,
      });
      return this.agent.post('/token')
        .auth('client', 'secret')
        .send({ assertion, grant_type: jwtBearer.grantType })
        .type('form')
        .expect(400)
        .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });
    });

    it('rejects the wrong authorization-server audience', async function () {
      const assertion = await signAssertion(this.jwtKeyPair.privateKey, {
        audience: 'https://other-as.example.com',
      });
      return this.agent.post('/token')
        .auth('client', 'secret')
        .send({ assertion, grant_type: jwtBearer.grantType })
        .type('form')
        .expect(400)
        .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });
    });

    it('applies the configured jti replay policy only after successful issuance', async function () {
      const assertion = await signAssertion(this.jwtKeyPair.privateKey, {
        audience: this.provider.issuer,
      });
      const request = (value = assertion) => this.agent.post('/token')
        .auth('client', 'secret')
        .send({ assertion: value, grant_type: jwtBearer.grantType })
        .type('form');

      await request().expect(200);
      await request()
        .expect(400)
        .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

      const concurrentAssertion = await signAssertion(this.jwtKeyPair.privateKey, {
        audience: this.provider.issuer,
      });
      const responses = await Promise.all([
        request(concurrentAssertion),
        request(concurrentAssertion),
      ]);
      expect(responses.map(({ status }) => status).sort()).to.deep.equal([200, 400]);
    });

    it('rejects malformed claims, RAR, disallowed algorithms, issuer, sub, exp, and nbf failures', async function () {
      const timestamp = now();
      const es384 = await generateKeyPair('ES384');
      const cases = [
        'not-a-jwt',
        await signClaims(es384.privateKey, {
          aud: this.provider.issuer,
          exp: timestamp + 60,
          iss: JWT_ISSUER,
          sub: 'external-user',
        }, 'ES384'),
        await signClaims(this.jwtKeyPair.privateKey, {
          aud: this.provider.issuer,
          authorization_details: [{ amount: '10', locations: [API], type: 'payment' }],
          exp: timestamp + 60,
          iss: JWT_ISSUER,
          jti: randomUUID(),
          sub: 'external-user',
        }),
        await signClaims(this.jwtKeyPair.privateKey, {
          aud: this.provider.issuer,
          exp: timestamp + 60,
          iss: 'https://untrusted.example.com',
          sub: 'external-user',
        }),
        await signClaims(this.jwtKeyPair.privateKey, {
          aud: this.provider.issuer,
          exp: timestamp + 60,
          iss: JWT_ISSUER,
        }),
        await signClaims(this.jwtKeyPair.privateKey, {
          aud: this.provider.issuer,
          iss: JWT_ISSUER,
          sub: 'external-user',
        }),
        await signClaims(this.jwtKeyPair.privateKey, {
          aud: this.provider.issuer,
          exp: timestamp - 1,
          iss: JWT_ISSUER,
          sub: 'external-user',
        }),
        await signClaims(this.jwtKeyPair.privateKey, {
          aud: this.provider.issuer,
          exp: timestamp + 180,
          iss: JWT_ISSUER,
          nbf: timestamp + 120,
          sub: 'external-user',
        }),
        await signClaims(this.jwtKeyPair.privateKey, {
          aud: this.provider.issuer,
          exp: timestamp + 60,
          iss: JWT_ISSUER,
          sub: 'external-user',
        }),
        await signClaims(this.jwtKeyPair.privateKey, {
          aud: this.provider.issuer,
          exp: timestamp + 60,
          iss: JWT_ISSUER,
          jti: randomUUID(),
          scope: {},
          sub: 'external-user',
        }),
        await signClaims(this.jwtKeyPair.privateKey, {
          aud: this.provider.issuer,
          exp: timestamp + 60,
          iss: JWT_ISSUER,
          jti: randomUUID(),
          resource: {},
          sub: 'external-user',
        }),
      ];

      for (const assertion of cases) {
        await this.agent.post('/token')
          .auth('client', 'secret')
          .send({ assertion, grant_type: jwtBearer.grantType })
          .type('form')
          .expect(400)
          .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });
      }
    });
  });

  describe('RFC 7522 SAML bearer', () => {
    it('issues from the normalized result of an injected secure verifier', async function () {
      const assertion = encodeSamlFixture({ audiences: [this.provider.issuer] });
      const response = await this.agent.post('/token')
        .auth('client', 'secret')
        .send({ assertion, grant_type: saml2Bearer.grantType })
        .type('form')
        .expect(200);

      expect(response.body).to.include({
        resource: API,
        scope: 'api:read',
        token_type: 'Bearer',
      });
      const token = await this.provider.AccessToken.find(response.body.access_token);
      expect(token).to.include({ accountId: 'saml-user', aud: API });
    });

    it('sanitizes verifier failures', function () {
      const assertion = encodeSamlFixture({
        audiences: [this.provider.issuer],
        signature: 'invalid',
      });
      return this.agent.post('/token')
        .auth('client', 'secret')
        .send({ assertion, grant_type: saml2Bearer.grantType })
        .type('form')
        .expect(400)
        .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });
    });
  });
});
