import { describe, before, beforeEach, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { importJWK } from 'jose';
import sinon from 'sinon';

import * as JWT from '../../lib/helpers/jwt.js';
import Provider from '../../lib/index.js';
import bootstrap from '../test_helper.js';
import { rarState, resetRarState } from './rich_authorization_requests.config.js';

const API = 'https://api.example.com';
const CONSENT_DETAILS = [{
  type: 'payment',
  actions: ['initiate'],
  currency: 'EUR',
  amount: 10,
}];

function redirectParameters(location) {
  const target = new URL(location, 'https://client.example.com');
  return new URLSearchParams(target.hash ? target.hash.slice(1) : target.search);
}

function interactionFromResponse(test, response) {
  const { pathname } = new URL(response.headers.location, test.provider.issuer);
  const uid = pathname.split('/').at(-1);
  return test.TestAdapter.for('Interaction').syncFind(uid);
}

async function authorizationResponse(test, authorizationDetails, overrides = {}) {
  const auth = new test.AuthorizationRequest({
    response_type: 'code',
    resource: API,
    authorization_details: typeof authorizationDetails === 'string'
      ? authorizationDetails
      : JSON.stringify(authorizationDetails),
    ...overrides,
  });

  const response = await test.wrap({ route: '/auth', verb: 'get', auth }).expect(303);
  return {
    auth,
    params: redirectParameters(response.headers.location),
    response,
  };
}

async function expectAuthorizationError(
  test,
  authorizationDetails,
  error,
  errorDescription,
  overrides,
) {
  const { auth, params } = await authorizationResponse(
    test,
    authorizationDetails,
    overrides,
  );

  assert.equal(params.get('error'), error);
  assert.equal(params.get('error_description'), errorDescription);
  assert.equal(params.get('state'), auth.state);
}

describe('Rich Authorization Requests', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  beforeEach(() => {
    resetRarState();
  }, { timeout: 3000 });

  describe('stable configuration and discovery', () => {
    const fixture1 = Object.create(fixture);

    it('does not accept the former experimental acknowledgement', { timeout: 3000 }, () => {
      assert.throws(() => new Provider('https://op.example.com', {
        features: {
          resourceIndicators: { enabled: true },
          richAuthorizationRequests: {
            enabled: true,
            ack: 'experimental-01',
            types: {
              payment: { validate() {} },
            },
          },
        },
      }), (error) => { assert.ok(error.message.includes('richAuthorizationRequests feature is now stable, the ack experimental-01 is no longer valid')); return true; });
    });

    it('does not accept former experimental callback names', { timeout: 3000 }, () => {
      assert.throws(() => new Provider('https://op.example.com', {
        features: {
          resourceIndicators: { enabled: true },
          richAuthorizationRequests: {
            enabled: true,
            types: {
              payment: { validate() {} },
            },
            rarForCodeResponse() {},
          },
        },
      }), (error) => { assert.ok(error.message.includes('Unknown feature configuration: richAuthorizationRequests.rarForCodeResponse')); return true; });
    });

    for (const callback of [
      'authorizationDetailsForGrantSource',
      'authorizationDetailsForAccessToken',
      'authorizationDetailsForIntrospection',
    ]) {
      it(`rejects a non-function ${callback} policy`, { timeout: 3000 }, () => {
        assert.throws(() => new Provider('https://op.example.com', {
          features: {
            resourceIndicators: { enabled: true },
            richAuthorizationRequests: {
              enabled: true,
              types: {
                payment: { validate() {} },
              },
              [callback]: 1,
            },
          },
        }), (error) => { assert.ok(error instanceof TypeError); assert.ok(error.message.includes(`features.richAuthorizationRequests.${callback} must be a function`)); return true; });
      });
    }

    it('advertises its supported authorization detail types', { timeout: 3000 }, () => fixture1.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect((response) => {
          ((actual) => { assert.ok('authorization_details_types_supported' in Object(actual)); assert.deepEqual(actual.authorization_details_types_supported, ['account_information', 'payment']); })(response.body);
        }));
  });

  describe('authorization request validation', () => {
    const fixture2 = Object.create(fixture);

    it('rejects malformed JSON', { timeout: 3000 }, () => expectAuthorizationError(
        fixture2,
        '[',
        'invalid_authorization_details',
        'could not parse the authorization_details parameter JSON',
      ));

    it('rejects a non-array value', { timeout: 3000 }, () => expectAuthorizationError(
        fixture2,
        {},
        'invalid_authorization_details',
        'authorization_details parameter should be a JSON array',
      ));

    it('rejects a non-object array member', { timeout: 3000 }, () => expectAuthorizationError(
        fixture2,
        [null],
        'invalid_authorization_details',
        'authorization_details parameter members should be a JSON object',
      ));

    it('rejects a missing type', { timeout: 3000 }, () => expectAuthorizationError(
        fixture2,
        [{}],
        'invalid_authorization_details',
        "authorization_details parameter members' type attribute must be a non-empty string (authorization details index 0)",
      ));

    it('rejects an empty type', { timeout: 3000 }, () => expectAuthorizationError(
        fixture2,
        [{ type: '' }],
        'invalid_authorization_details',
        "authorization_details parameter members' type attribute must be a non-empty string (authorization details index 0)",
      ));

    for (const type of ['unknown', 'toString']) {
      it(`rejects the unsupported ${type} type`, { timeout: 3000 }, () => expectAuthorizationError(
          fixture2,
          [{ type }],
          'invalid_authorization_details',
          'unsupported authorization details type value (authorization details index 0)',
        ));
    }

    for (const field of ['locations', 'actions', 'datatypes', 'privileges']) {
      it(`validates the common ${field} field`, { timeout: 3000 }, () => expectAuthorizationError(
          fixture2,
          [{ type: 'payment', [field]: [''] }],
          'invalid_authorization_details',
          `'${field}' must be an array of non-empty strings (authorization details index 0)`,
        ));
    }

    it('validates the common identifier field', { timeout: 3000 }, () => expectAuthorizationError(
        fixture2,
        [{ type: 'payment', identifier: '' }],
        'invalid_authorization_details',
        "'identifier' must be a non-empty string (authorization details index 0)",
      ));

    it('enforces the client authorization detail type allowlist', { timeout: 3000 }, () => expectAuthorizationError(
        fixture2,
        [{ type: 'account_information' }],
        'invalid_authorization_details',
        "authorization details type 'account_information' is not allowed for this client",
      ));

    it('awaits a strict type validator that rejects unknown fields', { timeout: 3000 }, async () => {
      const detail = { type: 'payment', unexpected: true };

      await expectAuthorizationError(
        fixture2,
        [detail],
        'invalid_authorization_details',
        "unexpected payment authorization detail field 'unexpected'",
      );

      assert.deepEqual(rarState.validationCalls, [detail]);
    });

    it('applies type-specific value validation', { timeout: 3000 }, () => expectAuthorizationError(
        fixture2,
        [{ type: 'payment', currency: 'usd' }],
        'invalid_authorization_details',
        "'currency' must be a three-letter uppercase code",
      ));

    it('normalizes an empty array and continues authorization', { timeout: 3000 }, async () => {
      const { params, response } = await authorizationResponse(fixture2, []);
      const target = new URL(response.headers.location, fixture2.provider.issuer);

      assert.equal(params.has('error'), false);
      assert.match(target.pathname, new RegExp(`^${fixture2.suitePath('/interaction/')}`));
      assert.equal(rarState.validationCalls.length, 0);
    });

    it('accepts a valid detail after asynchronous type validation', { timeout: 3000 }, async () => {
      const detail = {
        type: 'payment',
        actions: ['initiate'],
        currency: 'EUR',
        amount: 10,
      };
      const { params, response } = await authorizationResponse(fixture2, [detail]);
      const target = new URL(response.headers.location, fixture2.provider.issuer);

      assert.equal(params.has('error'), false);
      assert.match(target.pathname, new RegExp(`^${fixture2.suitePath('/interaction/')}`));
      assert.deepEqual(rarState.validationCalls, [detail]);
    });
  });

  describe('authorization consent', () => {
    const fixture3 = Object.create(fixture);

    beforeEach(() => fixture3.login({ accountId: 'account', scope: 'openid' }), { timeout: 3000 });

    afterEach(() => fixture3.logout(), { timeout: 3000 });

    it('prompts for RAR without requiring a scope parameter', { timeout: 3000 }, async () => {
      const auth = new fixture3.AuthorizationRequest({
        response_type: 'code',
        resource: API,
        authorization_details: JSON.stringify(CONSENT_DETAILS),
      });

      const response = await fixture3.wrap({ route: '/auth', verb: 'get', auth }).expect(303);
      const interaction = interactionFromResponse(fixture3, response);

      assert.ok(!('scope' in Object(interaction.params)));
      ((actual) => { assert.ok("name" in Object(actual)); assert.deepEqual(actual.name, 'consent'); assert.ok("reasons" in Object(actual)); assert.deepEqual(actual.reasons, ['rar_prompt']); })(interaction.prompt);
      assert.deepEqual(interaction.prompt.details, { rar: CONSENT_DETAILS });
    });

    it('presents scope and RAR requirements in the same consent prompt', { timeout: 3000 }, async () => {
      const auth = new fixture3.AuthorizationRequest({
        response_type: 'code',
        scope: 'api:read',
        resource: API,
        authorization_details: JSON.stringify(CONSENT_DETAILS),
      });

      const response = await fixture3.wrap({ route: '/auth', verb: 'get', auth }).expect(303);
      const interaction = interactionFromResponse(fixture3, response);

      assert.equal(interaction.prompt.name, 'consent');
      ((actual) => { assert.ok(Array.isArray(actual)); assert.ok(['rs_scopes_missing', 'rar_prompt'].every((value) => actual.includes(value))); })(interaction.prompt.reasons);
      ((actual) => { assert.ok("missingResourceScopes" in Object(actual)); assert.deepEqual(actual.missingResourceScopes, { [API]: ['api:read'] }); assert.ok("rar" in Object(actual)); assert.deepEqual(actual.rar, CONSENT_DETAILS); })(interaction.prompt.details);
    });
  });

  describe('protected authorization requests', () => {
    const fixture4 = Object.create(fixture);

    before(async () => {
      const client = await fixture4.provider.Client.find('client');
      fixture4.requestObjectKey = await importJWK(
        client.symmetricKeyStore.selectForSign({ alg: 'HS256' })[0],
      );
    }, { timeout: 3000 });

    beforeEach(() => fixture4.login({ accountId: 'account', scope: 'openid' }), { timeout: 3000 });

    afterEach(() => fixture4.logout(), { timeout: 3000 });

    it('conveys RAR through a Pushed Authorization Request', { timeout: 3000 }, async () => {
      const { body: { request_uri: requestUri } } = await fixture4.agent.post('/request')
        .auth('client', 'secret')
        .type('form')
        .send({
          authorization_details: JSON.stringify(CONSENT_DETAILS),
          client_id: 'client',
          redirect_uri: 'https://client.example.com/cb',
          resource: API,
          response_type: 'code',
          state: 'par-state',
        })
        .expect(201);

      const response = await fixture4.agent.get('/auth')
        .query({ client_id: 'client', request_uri: requestUri })
        .expect(303);
      const interaction = interactionFromResponse(fixture4, response);

      assert.equal(interaction.params.authorization_details, JSON.stringify(CONSENT_DETAILS));
      assert.equal(interaction.params.state, 'par-state');
      assert.ok(interaction.prompt.reasons.includes('rar_prompt'));
      assert.deepEqual(interaction.prompt.details.rar, CONSENT_DETAILS);
    });

    it('conveys RAR as a Request Object JSON claim', { timeout: 3000 }, async () => {
      const request = await JWT.sign({
        aud: fixture4.provider.issuer,
        authorization_details: CONSENT_DETAILS,
        client_id: 'client',
        iss: 'client',
        jti: randomBytes(16).toString('base64url'),
        redirect_uri: 'https://client.example.com/cb',
        resource: API,
        response_type: 'code',
        state: 'jar-state',
      }, fixture4.requestObjectKey, 'HS256', { expiresIn: 30 });

      const response = await fixture4.agent.get('/auth')
        .query({ client_id: 'client', request })
        .expect(303);
      const interaction = interactionFromResponse(fixture4, response);

      assert.equal(interaction.params.authorization_details, JSON.stringify(CONSENT_DETAILS));
      assert.equal(interaction.params.state, 'jar-state');
      assert.ok(interaction.prompt.reasons.includes('rar_prompt'));
      assert.deepEqual(interaction.prompt.details.rar, CONSENT_DETAILS);
    });
  });

  describe('retained provider profile restrictions', () => {
    const fixture5 = Object.create(fixture);

    for (const responseType of ['id_token token', 'id_token', 'code token', 'none']) {
      it(`rejects response_type=${responseType}`, { timeout: 3000 }, () => expectAuthorizationError(
          fixture5,
          [{ type: 'payment' }],
          'invalid_request',
          'authorization_details parameter is not supported for this response_type',
          {
            response_type: responseType,
            scope: responseType.includes('id_token') ? 'openid' : undefined,
          },
        ));
    }

    it('requires an explicit or defaulted resource', { timeout: 3000 }, () => expectAuthorizationError(
        fixture5,
        [{ type: 'payment' }],
        'invalid_target',
        'resource indicator must be provided or defaulted to when Rich Authorization Requests are used',
        { resource: undefined },
      ));
  });

  describe('client_credentials', () => {
    const fixture6 = Object.create(fixture);

    it('rejects token-request RAR without an explicit or defaulted resource', { timeout: 3000 }, () => fixture6.agent.post('/token')
        .auth('client', 'secret')
        .type('form')
        .send({
          grant_type: 'client_credentials',
          scope: 'api:read',
          authorization_details: JSON.stringify([{ type: 'payment' }]),
        })
        .expect(400)
        .expect({
          error: 'invalid_target',
          error_description: 'resource indicator must be provided or defaulted to when Rich Authorization Requests are used',
        }));

    it('assigns and returns the access token authorization details', { timeout: 3000 }, async () => {
      const detail = {
        type: 'payment',
        actions: ['initiate'],
        currency: 'EUR',
        amount: 10,
      };
      const saved = sinon.spy();
      fixture6.provider.once('client_credentials.saved', saved);

      const response = await fixture6.agent.post('/token')
        .auth('client', 'secret')
        .type('form')
        .send({
          grant_type: 'client_credentials',
          scope: 'api:read',
          resource: API,
          authorization_details: JSON.stringify([detail]),
        })
        .expect(200);

      assert.equal(rarState.accessTokenCalls.length, 1);
      const [call] = rarState.accessTokenCalls;
      assert.equal(call.grantType, 'client_credentials');
      assert.equal(call.source, undefined);
      ((actual) => { assert.ok('kind' in Object(actual)); assert.equal(actual.kind, 'ClientCredentials'); })(call.token);
      assert.equal(call.resource, API);

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(saved);
      const token = saved.firstCall.args[0];
      assert.equal(token, call.token);
      assert.deepEqual(token.rar, [detail]);
      assert.deepEqual(response.body.authorization_details, token.rar);
    });

    it('normalizes an empty policy result to undefined', { timeout: 3000 }, async () => {
      rarState.emptyAccessTokenResult = true;
      const saved = sinon.spy();
      fixture6.provider.once('client_credentials.saved', saved);

      const response = await fixture6.agent.post('/token')
        .auth('client', 'secret')
        .type('form')
        .send({
          grant_type: 'client_credentials',
          scope: 'api:read',
          resource: API,
          authorization_details: JSON.stringify([{ type: 'payment' }]),
        })
        .expect(200);

      assert.equal(saved.firstCall.args[0].rar, undefined);
      assert.ok(!('authorization_details' in Object(response.body)));
    });

    it('treats malformed callback output as a server configuration error', { timeout: 3000 }, async () => {
      rarState.invalidAccessTokenResult = true;
      const serverError = sinon.spy();
      const saved = sinon.spy();
      fixture6.provider.once('server_error', serverError);
      fixture6.provider.once('client_credentials.saved', saved);

      await fixture6.agent.post('/token')
        .auth('client', 'secret')
        .type('form')
        .send({
          grant_type: 'client_credentials',
          scope: 'api:read',
          resource: API,
          authorization_details: JSON.stringify([{ type: 'payment' }]),
        })
        .expect(500)
        .expect({
          error: 'server_error',
          error_description: 'oops! something went wrong',
        });

      ((actual) => { assert.ok('called' in Object(actual)); assert.equal(actual.called, false); })(saved);
      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(serverError);
      assert.ok(serverError.firstCall.args[1] instanceof TypeError);
      assert.equal(serverError.firstCall.args[1].message, 'authorization details policy result members should be a JSON object');
    });
  });
});
