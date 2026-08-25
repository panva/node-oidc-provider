import { randomBytes } from 'node:crypto';

import { expect } from 'chai';
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

  expect(params.get('error')).to.equal(error);
  expect(params.get('error_description')).to.equal(errorDescription);
  expect(params.get('state')).to.equal(auth.state);
}

describe('Rich Authorization Requests', () => {
  before(bootstrap(import.meta.url));

  beforeEach(() => {
    resetRarState();
  });

  describe('stable configuration and discovery', () => {
    it('does not accept the former experimental acknowledgement', () => {
      expect(() => new Provider('https://op.example.com', {
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
      })).to.throw(
        'richAuthorizationRequests feature is now stable, the ack experimental-01 is no longer valid',
      );
    });

    it('does not accept former experimental callback names', () => {
      expect(() => new Provider('https://op.example.com', {
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
      })).to.throw(
        'Unknown feature configuration: richAuthorizationRequests.rarForCodeResponse',
      );
    });

    for (const callback of [
      'authorizationDetailsForGrantSource',
      'authorizationDetailsForAccessToken',
      'authorizationDetailsForIntrospection',
    ]) {
      it(`rejects a non-function ${callback} policy`, () => {
        expect(() => new Provider('https://op.example.com', {
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
        })).to.throw(
          TypeError,
          `features.richAuthorizationRequests.${callback} must be a function`,
        );
      });
    }

    it('advertises its supported authorization detail types', function () {
      return this.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('authorization_details_types_supported')
            .that.deep.equals(['account_information', 'payment']);
        });
    });
  });

  describe('authorization request validation', () => {
    it('rejects malformed JSON', function () {
      return expectAuthorizationError(
        this,
        '[',
        'invalid_authorization_details',
        'could not parse the authorization_details parameter JSON',
      );
    });

    it('rejects a non-array value', function () {
      return expectAuthorizationError(
        this,
        {},
        'invalid_authorization_details',
        'authorization_details parameter should be a JSON array',
      );
    });

    it('rejects a non-object array member', function () {
      return expectAuthorizationError(
        this,
        [null],
        'invalid_authorization_details',
        'authorization_details parameter members should be a JSON object',
      );
    });

    it('rejects a missing type', function () {
      return expectAuthorizationError(
        this,
        [{}],
        'invalid_authorization_details',
        "authorization_details parameter members' type attribute must be a non-empty string (authorization details index 0)",
      );
    });

    it('rejects an empty type', function () {
      return expectAuthorizationError(
        this,
        [{ type: '' }],
        'invalid_authorization_details',
        "authorization_details parameter members' type attribute must be a non-empty string (authorization details index 0)",
      );
    });

    for (const type of ['unknown', 'toString']) {
      it(`rejects the unsupported ${type} type`, function () {
        return expectAuthorizationError(
          this,
          [{ type }],
          'invalid_authorization_details',
          'unsupported authorization details type value (authorization details index 0)',
        );
      });
    }

    for (const field of ['locations', 'actions', 'datatypes', 'privileges']) {
      it(`validates the common ${field} field`, function () {
        return expectAuthorizationError(
          this,
          [{ type: 'payment', [field]: [''] }],
          'invalid_authorization_details',
          `'${field}' must be an array of non-empty strings (authorization details index 0)`,
        );
      });
    }

    it('validates the common identifier field', function () {
      return expectAuthorizationError(
        this,
        [{ type: 'payment', identifier: '' }],
        'invalid_authorization_details',
        "'identifier' must be a non-empty string (authorization details index 0)",
      );
    });

    it('enforces the client authorization detail type allowlist', function () {
      return expectAuthorizationError(
        this,
        [{ type: 'account_information' }],
        'invalid_authorization_details',
        "authorization details type 'account_information' is not allowed for this client",
      );
    });

    it('awaits a strict type validator that rejects unknown fields', async function () {
      const detail = { type: 'payment', unexpected: true };

      await expectAuthorizationError(
        this,
        [detail],
        'invalid_authorization_details',
        "unexpected payment authorization detail field 'unexpected'",
      );

      expect(rarState.validationCalls).to.deep.equal([detail]);
    });

    it('applies type-specific value validation', function () {
      return expectAuthorizationError(
        this,
        [{ type: 'payment', currency: 'usd' }],
        'invalid_authorization_details',
        "'currency' must be a three-letter uppercase code",
      );
    });

    it('normalizes an empty array and continues authorization', async function () {
      const { params, response } = await authorizationResponse(this, []);
      const target = new URL(response.headers.location, this.provider.issuer);

      expect(params.has('error')).to.be.false;
      expect(target.pathname).to.match(new RegExp(`^${this.suitePath('/interaction/')}`));
      expect(rarState.validationCalls).to.be.empty;
    });

    it('accepts a valid detail after asynchronous type validation', async function () {
      const detail = {
        type: 'payment',
        actions: ['initiate'],
        currency: 'EUR',
        amount: 10,
      };
      const { params, response } = await authorizationResponse(this, [detail]);
      const target = new URL(response.headers.location, this.provider.issuer);

      expect(params.has('error')).to.be.false;
      expect(target.pathname).to.match(new RegExp(`^${this.suitePath('/interaction/')}`));
      expect(rarState.validationCalls).to.deep.equal([detail]);
    });
  });

  describe('authorization consent', () => {
    beforeEach(function () {
      return this.login({ accountId: 'account', scope: 'openid' });
    });

    afterEach(function () {
      return this.logout();
    });

    it('prompts for RAR without requiring a scope parameter', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        resource: API,
        authorization_details: JSON.stringify(CONSENT_DETAILS),
      });

      const response = await this.wrap({ route: '/auth', verb: 'get', auth }).expect(303);
      const interaction = interactionFromResponse(this, response);

      expect(interaction.params).not.to.have.property('scope');
      expect(interaction.prompt).to.deep.include({
        name: 'consent',
        reasons: ['rar_prompt'],
      });
      expect(interaction.prompt.details).to.deep.equal({ rar: CONSENT_DETAILS });
    });

    it('presents scope and RAR requirements in the same consent prompt', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'api:read',
        resource: API,
        authorization_details: JSON.stringify(CONSENT_DETAILS),
      });

      const response = await this.wrap({ route: '/auth', verb: 'get', auth }).expect(303);
      const interaction = interactionFromResponse(this, response);

      expect(interaction.prompt.name).to.equal('consent');
      expect(interaction.prompt.reasons).to.include.members(['rs_scopes_missing', 'rar_prompt']);
      expect(interaction.prompt.details).to.deep.include({
        missingResourceScopes: { [API]: ['api:read'] },
        rar: CONSENT_DETAILS,
      });
    });
  });

  describe('protected authorization requests', () => {
    before(async function () {
      const client = await this.provider.Client.find('client');
      this.requestObjectKey = await importJWK(
        client.symmetricKeyStore.selectForSign({ alg: 'HS256' })[0],
      );
    });

    beforeEach(function () {
      return this.login({ accountId: 'account', scope: 'openid' });
    });

    afterEach(function () {
      return this.logout();
    });

    it('conveys RAR through a Pushed Authorization Request', async function () {
      const { body: { request_uri: requestUri } } = await this.agent.post('/request')
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

      const response = await this.agent.get('/auth')
        .query({ client_id: 'client', request_uri: requestUri })
        .expect(303);
      const interaction = interactionFromResponse(this, response);

      expect(interaction.params.authorization_details).to.equal(JSON.stringify(CONSENT_DETAILS));
      expect(interaction.params.state).to.equal('par-state');
      expect(interaction.prompt.reasons).to.include('rar_prompt');
      expect(interaction.prompt.details.rar).to.deep.equal(CONSENT_DETAILS);
    });

    it('conveys RAR as a Request Object JSON claim', async function () {
      const request = await JWT.sign({
        aud: this.provider.issuer,
        authorization_details: CONSENT_DETAILS,
        client_id: 'client',
        iss: 'client',
        jti: randomBytes(16).toString('base64url'),
        redirect_uri: 'https://client.example.com/cb',
        resource: API,
        response_type: 'code',
        state: 'jar-state',
      }, this.requestObjectKey, 'HS256', { expiresIn: 30 });

      const response = await this.agent.get('/auth')
        .query({ client_id: 'client', request })
        .expect(303);
      const interaction = interactionFromResponse(this, response);

      expect(interaction.params.authorization_details).to.equal(JSON.stringify(CONSENT_DETAILS));
      expect(interaction.params.state).to.equal('jar-state');
      expect(interaction.prompt.reasons).to.include('rar_prompt');
      expect(interaction.prompt.details.rar).to.deep.equal(CONSENT_DETAILS);
    });
  });

  describe('retained provider profile restrictions', () => {
    for (const responseType of ['id_token token', 'id_token', 'code token', 'none']) {
      it(`rejects response_type=${responseType}`, function () {
        return expectAuthorizationError(
          this,
          [{ type: 'payment' }],
          'invalid_request',
          'authorization_details parameter is not supported for this response_type',
          {
            response_type: responseType,
            scope: responseType.includes('id_token') ? 'openid' : undefined,
          },
        );
      });
    }

    it('requires an explicit or defaulted resource', function () {
      return expectAuthorizationError(
        this,
        [{ type: 'payment' }],
        'invalid_target',
        'resource indicator must be provided or defaulted to when Rich Authorization Requests are used',
        { resource: undefined },
      );
    });
  });

  describe('client_credentials', () => {
    it('rejects token-request RAR without an explicit or defaulted resource', function () {
      return this.agent.post('/token')
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
        });
    });

    it('assigns and returns the access token authorization details', async function () {
      const detail = {
        type: 'payment',
        actions: ['initiate'],
        currency: 'EUR',
        amount: 10,
      };
      const saved = sinon.spy();
      this.provider.once('client_credentials.saved', saved);

      const response = await this.agent.post('/token')
        .auth('client', 'secret')
        .type('form')
        .send({
          grant_type: 'client_credentials',
          scope: 'api:read',
          resource: API,
          authorization_details: JSON.stringify([detail]),
        })
        .expect(200);

      expect(rarState.accessTokenCalls).to.have.lengthOf(1);
      const [call] = rarState.accessTokenCalls;
      expect(call.grantType).to.equal('client_credentials');
      expect(call.source).to.be.undefined;
      expect(call.token).to.have.property('kind', 'ClientCredentials');
      expect(call.resource).to.equal(API);

      expect(saved).to.have.property('calledOnce', true);
      const token = saved.firstCall.args[0];
      expect(token).to.equal(call.token);
      expect(token.rar).to.deep.equal([detail]);
      expect(response.body.authorization_details).to.deep.equal(token.rar);
    });

    it('normalizes an empty policy result to undefined', async function () {
      rarState.emptyAccessTokenResult = true;
      const saved = sinon.spy();
      this.provider.once('client_credentials.saved', saved);

      const response = await this.agent.post('/token')
        .auth('client', 'secret')
        .type('form')
        .send({
          grant_type: 'client_credentials',
          scope: 'api:read',
          resource: API,
          authorization_details: JSON.stringify([{ type: 'payment' }]),
        })
        .expect(200);

      expect(saved.firstCall.args[0].rar).to.be.undefined;
      expect(response.body).not.to.have.property('authorization_details');
    });

    it('treats malformed callback output as a server configuration error', async function () {
      rarState.invalidAccessTokenResult = true;
      const serverError = sinon.spy();
      const saved = sinon.spy();
      this.provider.once('server_error', serverError);
      this.provider.once('client_credentials.saved', saved);

      await this.agent.post('/token')
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

      expect(saved).to.have.property('called', false);
      expect(serverError).to.have.property('calledOnce', true);
      expect(serverError.firstCall.args[1]).to.be.instanceOf(TypeError);
      expect(serverError.firstCall.args[1].message).to.equal(
        'authorization details policy result members should be a JSON object',
      );
    });
  });
});
