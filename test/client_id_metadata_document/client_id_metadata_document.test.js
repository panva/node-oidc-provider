import { describe, before, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import timekeeper from 'timekeeper';

import bootstrap, { mock } from '../test_helper.js';
import Provider from '../../lib/index.js';
import als from '../../lib/helpers/als.js';
import {
  isValidClientIdUrl,
  resolveClientByMetadataDocument,
} from '../../lib/helpers/client_id_metadata_document.js';
import keys, { stripPrivateJWKFields } from '../keys.js';
import { TestAdapter } from '../models.js';

const CLIENT_ID_URL = 'https://app.example.com/metadata';
const publicKey = stripPrivateJWKFields(keys[0]);
const VALID_METADATA = {
  client_id: CLIENT_ID_URL,
  redirect_uris: ['https://app.example.com/cb'],
  token_endpoint_auth_method: 'none',
  client_name: 'Test App',
};

function createProvider(feature = {}, configuration = {}) {
  return new Provider('https://op.example.com', {
    ...configuration,
    adapter: TestAdapter,
    features: {
      rpMetadataChoices: { enabled: false },
      ...configuration.features,
      clientIdMetadataDocument: {
        enabled: true,
        ack: 'draft-03',
        ...feature,
      },
    },
    fetch: (url, options) => {
      delete options.dispatcher;
      return globalThis.fetch(url, options);
    },
  });
}

function resolve(provider, id, ctx = {}) {
  return als.run(ctx, () => resolveClientByMetadataDocument(provider, id));
}

function mockMetadata(id, metadata = {}, maxAge = 3600) {
  const url = new URL(id);
  return mock(url.origin)
    .intercept({ path: `${url.pathname}${url.search}` })
    .reply(200, JSON.stringify({
      client_id: id,
      redirect_uris: ['https://client.example.com/cb'],
      token_endpoint_auth_method: 'none',
      ...metadata,
    }), {
      headers: {
        'content-type': 'application/json',
        'cache-control': `max-age=${maxAge}`,
      },
    });
}

describe('Client ID Metadata Document', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  describe('isValidClientIdUrl', () => {
    it('accepts a valid HTTPS URL with a path', { timeout: 3000 }, () => {
      assert.equal(isValidClientIdUrl('https://example.com/client'), true);
    });

    it('accepts URLs with a port', { timeout: 3000 }, () => {
      assert.equal(isValidClientIdUrl('https://example.com:8443/client'), true);
    });

    it('accepts URLs with a query string', { timeout: 3000 }, () => {
      assert.equal(isValidClientIdUrl('https://example.com/client?id=123'), true);
    });

    it('accepts URLs with an uppercase scheme', { timeout: 3000 }, () => {
      assert.equal(isValidClientIdUrl('HTTPS://example.com/client'), true);
    });

    it('rejects root-equivalent URLs', { timeout: 3000 }, () => {
      assert.equal(isValidClientIdUrl('https://example.com'), false);
      assert.equal(isValidClientIdUrl('https://example.com/'), false);
      assert.equal(isValidClientIdUrl('https://example.com?foo=bar'), false);
      assert.equal(isValidClientIdUrl('https://example.com/?foo=bar'), false);
    });

    it('rejects non-HTTPS URLs', { timeout: 3000 }, () => {
      assert.equal(isValidClientIdUrl('http://example.com/client'), false);
    });

    it('rejects URLs with single-dot path segments', { timeout: 3000 }, () => {
      assert.equal(isValidClientIdUrl('https://example.com/./client'), false);
    });

    it('rejects URLs with double-dot path segments', { timeout: 3000 }, () => {
      assert.equal(isValidClientIdUrl('https://example.com/../client'), false);
      assert.equal(isValidClientIdUrl('https://example.com/a/../client'), false);
    });

    it('rejects URLs with percent-encoded dot path segments', { timeout: 3000 }, () => {
      assert.equal(isValidClientIdUrl('https://example.com/%2e/client'), false);
      assert.equal(isValidClientIdUrl('https://example.com/%2E/client'), false);
      assert.equal(isValidClientIdUrl('https://example.com/%2e%2e/client'), false);
      assert.equal(isValidClientIdUrl('https://example.com/.%2e/client'), false);
      assert.equal(isValidClientIdUrl('https://example.com/%2e./client'), false);
      assert.equal(isValidClientIdUrl('https://example.com/client/%2e'), false);
      assert.equal(isValidClientIdUrl('https://example.com/client/%2e%2e'), false);
    });

    it('accepts path segments that only look like double-encoded dot segments', { timeout: 3000 }, () => {
      assert.equal(isValidClientIdUrl('https://example.com/%252e/client'), true);
    });

    it('rejects URLs with a fragment', { timeout: 3000 }, () => {
      assert.equal(isValidClientIdUrl('https://example.com/client#frag'), false);
      assert.equal(isValidClientIdUrl('https://example.com/client#'), false);
      assert.equal(isValidClientIdUrl('https://example.com/client?#'), false);
    });

    it('rejects URLs with a username', { timeout: 3000 }, () => {
      assert.equal(isValidClientIdUrl('https://user@example.com/client'), false);
      assert.equal(isValidClientIdUrl('https://@example.com/client'), false);
    });

    it('rejects URLs with a password', { timeout: 3000 }, () => {
      assert.equal(isValidClientIdUrl('https://user:pass@example.com/client'), false);
      assert.equal(isValidClientIdUrl('https://:@example.com/client'), false);
    });

    it('rejects non-URL strings', { timeout: 3000 }, () => {
      assert.equal(isValidClientIdUrl('not-a-url'), false);
    });

    it('rejects URLs that require WHATWG authority repair', { timeout: 3000 }, () => {
      assert.equal(isValidClientIdUrl('https:example.com/client'), false);
      assert.equal(isValidClientIdUrl('https:/example.com/client'), false);
      assert.equal(isValidClientIdUrl('https:///client'), false);
    });

    it('rejects URLs with raw characters WHATWG would strip or normalize', { timeout: 3000 }, () => {
      assert.equal(isValidClientIdUrl(' https://example.com/client'), false);
      assert.equal(isValidClientIdUrl('https://example.com/client '), false);
      assert.equal(isValidClientIdUrl('https://example.com/\tclient'), false);
      assert.equal(isValidClientIdUrl('https://example.com/\nclient'), false);
      assert.equal(isValidClientIdUrl('https://example.com\\client'), false);
      assert.equal(isValidClientIdUrl('https:\\\\example.com\\client'), false);
    });
  });

  describe('discovery', () => {
    const fixture2 = Object.create(fixture);

    it('includes client_id_metadata_document_supported', { timeout: 3000 }, () => fixture2.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect((response) => {
          ((actual) => { assert.ok('client_id_metadata_document_supported' in Object(actual)); assert.equal(actual.client_id_metadata_document_supported, true); })(response.body);
        }));
  });

  describe('client resolution via metadata document', () => {
    const fixture3 = Object.create(fixture);

    it('resolves a client from a valid metadata document', { timeout: 3000 }, () => {
      mock('https://app.example.com')
        .intercept({ path: '/metadata' })
        .reply(200, JSON.stringify(VALID_METADATA), {
          headers: { 'content-type': 'application/json' },
        });

      return fixture3.agent.get('/auth')
        .query({
          client_id: CLIENT_ID_URL,
          redirect_uri: 'https://app.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(303)
        .expect((response) => {
          const location = new URL(response.headers.location, fixture3.provider.issuer);
          assert.match(location.pathname, /\/interaction\//);
        });
    });

    it('static/adapter clients take precedence over metadata document resolution', { timeout: 3000 }, () => fixture3.agent.get('/auth')
        .query({
          client_id: 'client',
          redirect_uri: 'https://client.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(303)
        .expect((response) => {
          const location = new URL(response.headers.location, fixture3.provider.issuer);
          assert.match(location.pathname, /\/interaction\//);
        }));

    it('serves from cache on second request', { timeout: 3000 }, async () => {
      mock('https://cached.example.com')
        .intercept({ path: '/client' })
        .reply(200, JSON.stringify({
          client_id: 'https://cached.example.com/client',
          redirect_uris: ['https://cached.example.com/cb'],
          token_endpoint_auth_method: 'none',
        }), {
          headers: {
            'content-type': 'application/json',
            'cache-control': 'max-age=3600',
          },
        });

      // First request - fetches
      await fixture3.agent.get('/auth')
        .query({
          client_id: 'https://cached.example.com/client',
          redirect_uri: 'https://cached.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(303);

      // Second request - no additional mock needed, served from cache
      await fixture3.agent.get('/auth')
        .query({
          client_id: 'https://cached.example.com/client',
          redirect_uri: 'https://cached.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(303);
    });

    it('rejects when metadata document has mismatched client_id', { timeout: 3000 }, () => {
      mock('https://mismatch.example.com')
        .intercept({ path: '/client' })
        .reply(200, JSON.stringify({
          client_id: 'https://somewhere-else.example.com/client',
          redirect_uris: ['https://mismatch.example.com/cb'],
          token_endpoint_auth_method: 'none',
        }), {
          headers: { 'content-type': 'application/json' },
        });

      return fixture3.agent.get('/auth')
        .query({
          client_id: 'https://mismatch.example.com/client',
          redirect_uri: 'https://mismatch.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          assert.match(response.text, /invalid_client\b/);
        });
    });

    it('compares client_id values without default port normalization', { timeout: 3000 }, () => {
      mock('https://defaultport.example.com')
        .intercept({ path: '/client' })
        .reply(200, JSON.stringify({
          client_id: 'https://defaultport.example.com/client',
          redirect_uris: ['https://defaultport.example.com/cb'],
          token_endpoint_auth_method: 'none',
        }), {
          headers: { 'content-type': 'application/json' },
        });

      return fixture3.agent.get('/auth')
        .query({
          client_id: 'https://defaultport.example.com:443/client',
          redirect_uri: 'https://defaultport.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          assert.match(response.text, /invalid_client\b/);
        });
    });

    it('rejects when metadata document uses client_secret_basic', { timeout: 3000 }, () => {
      mock('https://secretauth.example.com')
        .intercept({ path: '/client' })
        .reply(200, JSON.stringify({
          client_id: 'https://secretauth.example.com/client',
          redirect_uris: ['https://secretauth.example.com/cb'],
          token_endpoint_auth_method: 'client_secret_basic',
        }), {
          headers: { 'content-type': 'application/json' },
        });

      return fixture3.agent.get('/auth')
        .query({
          client_id: 'https://secretauth.example.com/client',
          redirect_uri: 'https://secretauth.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          assert.match(response.text, /invalid_client\b/);
        });
    });

    it('rejects when metadata document uses client_secret_post', { timeout: 3000 }, () => {
      mock('https://secretpost.example.com')
        .intercept({ path: '/client' })
        .reply(200, JSON.stringify({
          client_id: 'https://secretpost.example.com/client',
          redirect_uris: ['https://secretpost.example.com/cb'],
          token_endpoint_auth_method: 'client_secret_post',
        }), {
          headers: { 'content-type': 'application/json' },
        });

      return fixture3.agent.get('/auth')
        .query({
          client_id: 'https://secretpost.example.com/client',
          redirect_uri: 'https://secretpost.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          assert.match(response.text, /invalid_client\b/);
        });
    });

    it('rejects when metadata document uses client_secret_jwt', { timeout: 3000 }, () => {
      mock('https://secretjwt.example.com')
        .intercept({ path: '/client' })
        .reply(200, JSON.stringify({
          client_id: 'https://secretjwt.example.com/client',
          redirect_uris: ['https://secretjwt.example.com/cb'],
          token_endpoint_auth_method: 'client_secret_jwt',
        }), {
          headers: { 'content-type': 'application/json' },
        });

      return fixture3.agent.get('/auth')
        .query({
          client_id: 'https://secretjwt.example.com/client',
          redirect_uri: 'https://secretjwt.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          assert.match(response.text, /invalid_client\b/);
        });
    });

    it('rejects when metadata document contains client_secret', { timeout: 3000 }, () => {
      mock('https://hassecret.example.com')
        .intercept({ path: '/client' })
        .reply(200, JSON.stringify({
          client_id: 'https://hassecret.example.com/client',
          redirect_uris: ['https://hassecret.example.com/cb'],
          token_endpoint_auth_method: 'none',
          client_secret: 'super-secret',
        }), {
          headers: { 'content-type': 'application/json' },
        });

      return fixture3.agent.get('/auth')
        .query({
          client_id: 'https://hassecret.example.com/client',
          redirect_uri: 'https://hassecret.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          assert.match(response.text, /invalid_client\b/);
        });
    });

    it('accepts public key material in an inline jwks', { timeout: 3000 }, () => {
      mock('https://publicjwks.example.com')
        .intercept({ path: '/client' })
        .reply(200, JSON.stringify({
          client_id: 'https://publicjwks.example.com/client',
          redirect_uris: ['https://publicjwks.example.com/cb'],
          token_endpoint_auth_method: 'private_key_jwt',
          jwks: { keys: [publicKey] },
        }), {
          headers: { 'content-type': 'application/json' },
        });

      return fixture3.agent.get('/auth')
        .query({
          client_id: 'https://publicjwks.example.com/client',
          redirect_uri: 'https://publicjwks.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(303)
        .expect((response) => {
          const location = new URL(response.headers.location, fixture3.provider.issuer);
          assert.match(location.pathname, /\/interaction\//);
        });
    });

    it('rejects private key material in an inline jwks', { timeout: 3000 }, () => {
      mock('https://privatejwks.example.com')
        .intercept({ path: '/client' })
        .reply(200, JSON.stringify({
          client_id: 'https://privatejwks.example.com/client',
          redirect_uris: ['https://privatejwks.example.com/cb'],
          token_endpoint_auth_method: 'none',
          jwks: { keys: [keys[0]] },
        }), {
          headers: { 'content-type': 'application/json' },
        });

      return fixture3.agent.get('/auth')
        .query({
          client_id: 'https://privatejwks.example.com/client',
          redirect_uri: 'https://privatejwks.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          assert.match(response.text, /invalid_client\b/);
        });
    });

    it('rejects when fetch fails (network error)', { timeout: 3000 }, () => {
      mock('https://fail.example.com')
        .intercept({ path: '/client' })
        .replyWithError(new Error('network error'));

      return fixture3.agent.get('/auth')
        .query({
          client_id: 'https://fail.example.com/client',
          redirect_uri: 'https://fail.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          assert.ok(response.text.includes('invalid_client'));
        });
    });

    it('rejects when a URI property uses http instead of https', { timeout: 3000 }, () => {
      mock('https://httpuri.example.com')
        .intercept({ path: '/client' })
        .reply(200, JSON.stringify({
          client_id: 'https://httpuri.example.com/client',
          redirect_uris: ['https://httpuri.example.com/cb'],
          token_endpoint_auth_method: 'none',
          client_uri: 'http://httpuri.example.com',
        }), {
          headers: { 'content-type': 'application/json' },
        });

      return fixture3.agent.get('/auth')
        .query({
          client_id: 'https://httpuri.example.com/client',
          redirect_uri: 'https://httpuri.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          assert.match(response.text, /invalid_client\b/);
        });
    });

    it('rejects when logo_uri is not an https URI', { timeout: 3000 }, () => {
      mock('https://badlogo.example.com')
        .intercept({ path: '/client' })
        .reply(200, JSON.stringify({
          client_id: 'https://badlogo.example.com/client',
          redirect_uris: ['https://badlogo.example.com/cb'],
          token_endpoint_auth_method: 'none',
          logo_uri: 'http://badlogo.example.com/logo.png',
        }), {
          headers: { 'content-type': 'application/json' },
        });

      return fixture3.agent.get('/auth')
        .query({
          client_id: 'https://badlogo.example.com/client',
          redirect_uri: 'https://badlogo.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          assert.match(response.text, /invalid_client\b/);
        });
    });

    it('accepts metadata with https URI properties', { timeout: 3000 }, () => {
      mock('https://gooduris.example.com')
        .intercept({ path: '/client' })
        .reply(200, JSON.stringify({
          client_id: 'https://gooduris.example.com/client',
          redirect_uris: ['https://gooduris.example.com/cb'],
          token_endpoint_auth_method: 'none',
          client_uri: 'https://gooduris.example.com',
          logo_uri: 'https://gooduris.example.com/logo.png',
          tos_uri: 'https://gooduris.example.com/tos',
          policy_uri: 'https://gooduris.example.com/policy',
        }), {
          headers: { 'content-type': 'application/json' },
        });

      return fixture3.agent.get('/auth')
        .query({
          client_id: 'https://gooduris.example.com/client',
          redirect_uri: 'https://gooduris.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(303)
        .expect((response) => {
          const location = new URL(response.headers.location, fixture3.provider.issuer);
          assert.match(location.pathname, /\/interaction\//);
        });
    });

    it('rejects when response is not 200', { timeout: 3000 }, () => {
      mock('https://notfound.example.com')
        .intercept({ path: '/client' })
        .reply(404, 'Not Found');

      return fixture3.agent.get('/auth')
        .query({
          client_id: 'https://notfound.example.com/client',
          redirect_uri: 'https://notfound.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          assert.ok(response.text.includes('invalid_client'));
        });
    });

    it('rejects when the server responds with a redirect', { timeout: 3000 }, () => {
      mock('https://redirect.example.com')
        .intercept({ path: '/client' })
        .reply(302, '', {
          headers: { location: 'https://redirect.example.com/other' },
        });

      return fixture3.agent.get('/auth')
        .query({
          client_id: 'https://redirect.example.com/client',
          redirect_uri: 'https://redirect.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          assert.ok(response.text.includes('invalid_client'));
        });
    });

    it('rejects when response is not valid JSON', { timeout: 3000 }, () => {
      let emitted;
      fixture3.provider.once('authorization.error', (_ctx, err) => {
        emitted = err;
      });

      mock('https://notjson.example.com')
        .intercept({ path: '/client' })
        .reply(200, 'this is not json', {
          headers: { 'content-type': 'application/json' },
        });

      return fixture3.agent.get('/auth')
        .query({
          client_id: 'https://notjson.example.com/client',
          redirect_uri: 'https://notjson.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          assert.ok(response.text.includes('invalid_client'));
          assert.ok(emitted.cause instanceof SyntaxError);
          assert.equal(emitted.error_detail, emitted.cause.message);
          assert.ok(!(response.text.includes(emitted.error_detail)));
        });
    });

    it('rejects when response body exceeds maxResponseSize', { timeout: 3000 }, () => {
      const largeBody = JSON.stringify({
        client_id: 'https://large.example.com/client',
        redirect_uris: ['https://large.example.com/cb'],
        token_endpoint_auth_method: 'none',
        padding: 'x'.repeat(10 * 1024),
      });

      mock('https://large.example.com')
        .intercept({ path: '/client' })
        .reply(200, largeBody, {
          headers: {
            'content-type': 'application/json',
            'transfer-encoding': 'chunked',
          },
        });

      return fixture3.agent.get('/auth')
        .query({
          client_id: 'https://large.example.com/client',
          redirect_uri: 'https://large.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          assert.ok(response.text.includes('invalid_client'));
        });
    });

    it('rejects early when Content-Length exceeds maxResponseSize', { timeout: 3000 }, () => {
      mock('https://largecl.example.com')
        .intercept({ path: '/client' })
        .reply(200, '{}', {
          headers: {
            'content-type': 'application/json',
            'content-length': '999999',
          },
        });

      return fixture3.agent.get('/auth')
        .query({
          client_id: 'https://largecl.example.com/client',
          redirect_uri: 'https://largecl.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          assert.ok(response.text.includes('invalid_client'));
        });
    });

    it('does not resolve non-URL client_id values', { timeout: 3000 }, () => fixture3.agent.get('/auth')
        .query({
          client_id: 'nonexistent-client',
          redirect_uri: 'https://client.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          assert.ok(response.text.includes('invalid_client'));
        }));

    it('does not resolve HTTP (non-HTTPS) client_id URLs', { timeout: 3000 }, () => fixture3.agent.get('/auth')
        .query({
          client_id: 'http://app.example.com/client',
          redirect_uri: 'https://app.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          assert.ok(response.text.includes('invalid_client'));
        }));
  });

  describe('client authentication metadata', () => {
    it('defaults to none when both authentication properties are omitted', { timeout: 3000 }, async () => {
      const provider = createProvider();
      const id = 'https://default-auth.example.com/client';
      mockMetadata(id, { token_endpoint_auth_method: undefined });

      assert.equal((await resolve(provider, id)).clientAuthMethod, 'none');
    });

    for (const enabled of [false, true]) {
      it(`ignores configured authentication defaults with rpMetadataChoices ${enabled ? 'enabled' : 'disabled'}`, { timeout: 3000 }, async () => {
        const provider = createProvider({}, {
          features: { rpMetadataChoices: { enabled } },
          clientDefaults: {
            token_endpoint_auth_method: 'private_key_jwt',
            token_endpoint_auth_methods_supported: ['private_key_jwt'],
          },
        });
        const id = 'https://configured-default-auth.example.com/client';
        mockMetadata(id, { token_endpoint_auth_method: undefined });

        assert.equal((await resolve(provider, id)).clientAuthMethod, 'none');
      });
    }

    it('preserves the default for clients registered by other means', { timeout: 3000 }, () => {
      const provider = createProvider();
      const client = new provider.Client({
        client_id: 'registered',
        client_secret: 'secret',
        redirect_uris: ['https://client.example.com/cb'],
      });

      assert.equal(client.clientAuthMethod, 'client_secret_basic');
    });

    for (const [methods, expected, jwks] of [
      [['unsupported', 'none'], 'none'],
      [['unsupported', 'private_key_jwt'], 'private_key_jwt', { keys: [publicKey] }],
    ]) {
      it(`selects ${expected} from authentication choices with rpMetadataChoices disabled`, { timeout: 3000 }, async () => {
        const provider = createProvider();
        const id = `https://auth-choices.example.com/${expected}`;
        mockMetadata(id, {
          token_endpoint_auth_method: undefined,
          token_endpoint_auth_methods_supported: methods,
          jwks,
        });

        assert.equal((await resolve(provider, id)).clientAuthMethod, expected);
      });
    }

    for (const enabled of [false, true]) {
      for (const methods of [['none', 'private_key_jwt'], ['private_key_jwt', 'none']]) {
        it(`selects private_key_jwt from ${JSON.stringify(methods)} with rpMetadataChoices ${enabled ? 'enabled' : 'disabled'}`, { timeout: 3000 }, async () => {
          const provider = createProvider({}, { features: { rpMetadataChoices: { enabled } } });
          const id = `https://auth-method-preference.example.com/${enabled}/${methods[0]}`;
          mockMetadata(id, {
            token_endpoint_auth_method: undefined,
            token_endpoint_auth_methods_supported: methods,
            jwks: { keys: [publicKey] },
          });

          assert.equal((await resolve(provider, id)).clientAuthMethod, 'private_key_jwt');
        });
      }

      it(`requires advertised private_key_jwt despite an explicit none and server ordering with rpMetadataChoices ${enabled ? 'enabled' : 'disabled'}`, { timeout: 3000 }, async () => {
        const provider = createProvider({}, {
          features: { rpMetadataChoices: { enabled } },
          clientAuthMethods: ['none', 'private_key_jwt'],
        });
        const id = `https://explicit-auth-method-preference.example.com/${enabled}`;
        mockMetadata(id, {
          token_endpoint_auth_method: 'none',
          token_endpoint_auth_methods_supported: ['none', 'private_key_jwt'],
          jwks: { keys: [publicKey] },
        });

        assert.equal((await resolve(provider, id)).clientAuthMethod, 'private_key_jwt');
      });
    }

    it('falls back to none when private_key_jwt is not supported by the authorization server', { timeout: 3000 }, async () => {
      const provider = createProvider({}, { clientAuthMethods: ['none'] });
      const id = 'https://auth-method-fallback.example.com/client';
      mockMetadata(id, {
        token_endpoint_auth_method: undefined,
        token_endpoint_auth_methods_supported: ['private_key_jwt', 'none'],
        jwks: { keys: [publicKey] },
      });

      assert.equal((await resolve(provider, id)).clientAuthMethod, 'none');
    });

    it('does not fall back to none unless the client advertises it', { timeout: 3000 }, async () => {
      const provider = createProvider({}, { clientAuthMethods: ['none'] });
      const id = 'https://auth-method-no-fallback.example.com/client';
      mockMetadata(id, {
        token_endpoint_auth_method: undefined,
        token_endpoint_auth_methods_supported: ['private_key_jwt'],
        jwks: { keys: [publicKey] },
      });

      await assert.rejects(resolve(provider, id), { error: 'invalid_client' });
    });

    it('requires client authentication when private_key_jwt and none are both advertised', { timeout: 3000 }, async () => {
      const id = 'https://auth-method-required.example.com/client';
      mockMetadata(id, {
        token_endpoint_auth_method: undefined,
        token_endpoint_auth_methods_supported: ['none', 'private_key_jwt'],
        jwks: { keys: [publicKey] },
      });

      await fixture.agent.post('/token')
        .type('form')
        .send({ client_id: id, grant_type: 'authorization_code', code: 'code' })
        .expect(401)
        .expect(({ body }) => assert.equal(body.error, 'invalid_client'));
    });

    it('rejects inconsistent singular and plural authentication methods', { timeout: 3000 }, async () => {
      const provider = createProvider();
      const id = 'https://inconsistent-auth.example.com/client';
      mockMetadata(id, {
        token_endpoint_auth_method: 'none',
        token_endpoint_auth_methods_supported: ['private_key_jwt'],
        jwks: { keys: [publicKey] },
      });

      await assert.rejects(resolve(provider, id), { error: 'invalid_client' });
    });

    for (const method of ['client_secret_basic', 'client_secret_post', 'client_secret_jwt']) {
      it(`rejects ${method} in authentication choices even when none can be selected`, { timeout: 3000 }, async () => {
        const provider = createProvider();
        const id = `https://secret-auth-choices.example.com/${method}`;
        mockMetadata(id, { token_endpoint_auth_methods_supported: ['none', method] });

        await assert.rejects(resolve(provider, id), { error: 'invalid_client' });
      });
    }

    for (const methods of [[], ['unsupported'], 'none', [null]]) {
      it(`rejects invalid or unsupported authentication choices ${JSON.stringify(methods)}`, { timeout: 3000 }, async () => {
        const provider = createProvider();
        const id = 'https://invalid-auth-choices.example.com/client';
        mockMetadata(id, {
          token_endpoint_auth_method: undefined,
          token_endpoint_auth_methods_supported: methods,
        });

        await assert.rejects(resolve(provider, id), { error: 'invalid_client' });
      });
    }

    for (const [name, metadata] of [
      ['private_key_jwt without keys', { token_endpoint_auth_method: 'private_key_jwt' }],
      ['private_key_jwt choices without keys', { token_endpoint_auth_method: undefined, token_endpoint_auth_methods_supported: ['private_key_jwt'] }],
      ['private_key_jwt and none choices without keys', { token_endpoint_auth_method: undefined, token_endpoint_auth_methods_supported: ['none', 'private_key_jwt'] }],
      ['both jwks and jwks_uri', { jwks: { keys: [publicKey] }, jwks_uri: 'https://client.example.com/jwks' }],
    ]) {
      it(`rejects ${name}`, { timeout: 3000 }, async () => {
        const provider = createProvider();
        const id = 'https://invalid-key-metadata.example.com/client';
        mockMetadata(id, metadata);

        await assert.rejects(resolve(provider, id), { error: 'invalid_client' });
      });
    }
  });

  describe('discovery error responses', () => {
    for (const path of ['/token', '/request']) {
      for (const [name, metadata] of [
        ['mismatched client_id', { client_id: 'https://other.example.com/client' }],
        ['invalid client metadata', { redirect_uris: ['not a uri'] }],
        ['unsupported authentication methods', {
          token_endpoint_auth_method: undefined,
          token_endpoint_auth_methods_supported: ['unsupported'],
        }],
      ]) {
        it(`returns invalid_client at ${path} for ${name}`, { timeout: 3000 }, async () => {
          const id = `https://endpoint-errors.example.com${path}/${name.replaceAll(' ', '-')}`;
          mockMetadata(id, metadata);

          await fixture.agent.post(path)
            .type('form')
            .send({
              client_id: id,
              grant_type: 'authorization_code',
              code: 'code',
              response_type: 'code',
              redirect_uri: 'https://client.example.com/cb',
              scope: 'openid',
            })
            .expect(400)
            .expect((response) => {
              assert.equal(response.body.error, 'invalid_client');
              assert.equal(response.headers.location, undefined);
            });
        });
      }
    }

    for (const failure of ['network', 'mismatched client_id']) {
      it(`does not redirect after a ${failure} failure when a later lookup succeeds`, { timeout: 3000 }, async () => {
        const id = `https://retry-authorization-error.example.com/${failure.replaceAll(' ', '-')}`;
        if (failure === 'network') {
          const url = new URL(id);
          mock(url.origin).intercept({ path: url.pathname }).replyWithError(new Error('network error'));
        } else {
          mockMetadata(id, { client_id: 'https://other.example.com/client' });
        }
        mockMetadata(id);

        await fixture.agent.get('/auth')
          .query({
            client_id: id,
            redirect_uri: 'https://client.example.com/cb',
            response_type: 'code',
            scope: 'openid',
          })
          .expect(400)
          .expect((response) => {
            assert.match(response.text, /invalid_client\b/);
            assert.equal(response.headers.location, undefined);
          });
      });
    }

    it('rejects client authentication when the document defaults to none', { timeout: 3000 }, async () => {
      const id = 'https://default-auth-token.example.com/client';
      mockMetadata(id, { token_endpoint_auth_method: undefined });

      await fixture.agent.post('/token')
        .auth(id, 'secret')
        .type('form')
        .send({ grant_type: 'authorization_code', code: 'code' })
        .expect(401)
        .expect((response) => {
          assert.equal(response.body.error, 'invalid_client');
        });
    });

    it('does not fetch root-equivalent client IDs', { timeout: 3000 }, async () => {
      let fetches = 0;
      const provider = createProvider({
        async allowFetch() {
          fetches += 1;
          return true;
        },
      });

      for (const id of ['https://root.example.com', 'https://root.example.com/', 'https://root.example.com?client=1', 'https://root.example.com/?client=1']) {
        assert.equal(await provider.Client.find(id), undefined);
      }
      assert.equal(fetches, 0);
    });

    it('rejects the authorization server issuer as a client ID before fetching', { timeout: 3000 }, async () => {
      const provider = new Provider('https://op.example.com/issuer', {
        adapter: TestAdapter,
        features: {
          clientIdMetadataDocument: {
            enabled: true,
            ack: 'draft-03',
            async allowFetch() {
              assert.fail('issuer identifiers must not be fetched');
            },
          },
        },
      });

      await assert.rejects(provider.Client.find(provider.issuer), {
        error: 'invalid_client',
        allow_redirect: false,
      });
    });
  });

  describe('metadata document cache', () => {
    afterEach(() => timekeeper.reset(), { timeout: 3000 });

    it('expires entries using their response-derived TTL', { timeout: 3000 }, async () => {
      const provider = createProvider();
      const id = 'https://ttl-cache.example.com/client';
      timekeeper.freeze(new Date('2026-08-03T12:00:00.000Z'));
      mockMetadata(id, { client_name: 'first' }, 30);

      const first = await resolve(provider, id);
      first.localMutation = true;
      const cached = await resolve(provider, id);

      assert.notEqual(cached, first);
      assert.equal(cached.clientName, 'first');
      assert.ok(!('localMutation' in Object(cached)));

      timekeeper.travel(Date.now() + 30_001);
      mockMetadata(id, { client_name: 'refreshed' }, 30);

      assert.equal((await resolve(provider, id)).clientName, 'refreshed');
    });

    it('evicts least-recently-used entries', { timeout: 3000 }, async () => {
      const provider = createProvider();
      const target = 'https://lru-cache.example.com/client/target';
      mockMetadata(target, { client_name: 'first' });
      assert.equal((await resolve(provider, target)).clientName, 'first');

      for (let i = 0; i < 200; i++) {
        const id = `https://lru-cache.example.com/client/${i}`;
        mockMetadata(id);
        await resolve(provider, id);
      }

      mockMetadata(target, { client_name: 'refetched' });
      assert.equal((await resolve(provider, target)).clientName, 'refetched');
    });

    it('does not cache invalid metadata documents', { timeout: 3000 }, async () => {
      const provider = createProvider();
      const id = 'https://invalid-cache.example.com/client';
      mockMetadata(id, { token_endpoint_auth_methods_supported: ['unsupported'], token_endpoint_auth_method: undefined });

      await assert.rejects(resolve(provider, id), { error: 'invalid_client' });

      mockMetadata(id, { client_name: 'corrected document' });
      assert.equal((await resolve(provider, id)).clientName, 'corrected document');
    });

    it('isolates entries per provider', { timeout: 3000 }, async () => {
      const firstProvider = createProvider();
      const secondProvider = createProvider();
      const id = 'https://isolated-cache.example.com/client';
      mockMetadata(id, { client_name: 'first provider' });
      mockMetadata(id, { client_name: 'second provider' });

      assert.equal((await resolve(firstProvider, id)).clientName, 'first provider');
      assert.equal((await resolve(secondProvider, id)).clientName, 'second provider');
    });
  });

  describe('concurrent metadata document fetches', () => {
    it('coalesces fetches while preserving request-scoped callbacks and clients', { timeout: 3000 }, async () => {
      const allowFetchCalls = [];
      const allowClientCalls = [];
      const provider = createProvider({
        async allowFetch(ctx, clientId) {
          allowFetchCalls.push({ ctx, clientId });
          return true;
        },
        async allowClient(ctx, client) {
          allowClientCalls.push({ ctx, client });
          return true;
        },
      });
      const id = 'https://concurrent-cache.example.com/client';
      const firstContext = { request: 'first' };
      const secondContext = { request: 'second' };
      const cachedContext = { request: 'cached' };
      mockMetadata(id, { client_name: 'shared' }).delay(20);

      const [first, second] = await Promise.all([
        resolve(provider, id, firstContext),
        resolve(provider, id, secondContext),
      ]);
      const cached = await resolve(provider, id, cachedContext);

      assert.notEqual(first, second);
      assert.notEqual(cached, first);
      assert.notEqual(cached, second);
      assert.equal(first.clientName, 'shared');
      assert.equal(second.clientName, 'shared');
      assert.equal(cached.clientName, 'shared');
      assert.deepEqual(allowFetchCalls, [
        { ctx: firstContext, clientId: id },
        { ctx: secondContext, clientId: id },
      ]);
      assert.equal(allowClientCalls.length, 3);
      assert.deepEqual(allowClientCalls[0], { ctx: firstContext, client: first });
      assert.deepEqual(allowClientCalls[1], { ctx: secondContext, client: second });
      assert.deepEqual(allowClientCalls[2], { ctx: cachedContext, client: cached });
    });

    it('clears failed in-flight fetches so later requests can retry', { timeout: 3000 }, async () => {
      const allowFetchCalls = [];
      const allowClientCalls = [];
      const provider = createProvider({
        async allowFetch(ctx, clientId) {
          allowFetchCalls.push({ ctx, clientId });
          return true;
        },
        async allowClient(ctx, client) {
          allowClientCalls.push({ ctx, client });
          return true;
        },
      });
      const id = 'https://concurrent-failure.example.com/client';
      const firstContext = { request: 'first' };
      const secondContext = { request: 'second' };
      const retryContext = { request: 'retry' };
      const url = new URL(id);
      mock(url.origin)
        .intercept({ path: url.pathname })
        .reply(200, 'not json', {
          headers: { 'content-type': 'application/json' },
        })
        .delay(20);

      const failed = await Promise.allSettled([
        resolve(provider, id, firstContext),
        resolve(provider, id, secondContext),
      ]);

      assert.equal(failed.length, 2);
      for (const result of failed) {
        assert.equal(result.status, 'rejected');
        assert.ok(result.reason.cause instanceof SyntaxError);
      }
      assert.deepEqual(allowFetchCalls, [
        { ctx: firstContext, clientId: id },
        { ctx: secondContext, clientId: id },
      ]);
      assert.equal(allowClientCalls.length, 0);

      mockMetadata(id, { client_name: 'retry' });
      const retried = await resolve(provider, id, retryContext);

      assert.equal(retried.clientName, 'retry');
      assert.deepEqual(allowFetchCalls, [
        { ctx: firstContext, clientId: id },
        { ctx: secondContext, clientId: id },
        { ctx: retryContext, clientId: id },
      ]);
      assert.deepEqual(allowClientCalls, [{ ctx: retryContext, client: retried }]);
    });
  });

  describe('unsupported metadata value filtering', () => {
    const fixture6 = Object.create(fixture);

    it('filters unsupported grant_types and keeps supported ones', { timeout: 3000 }, () => {
      mock('https://filter-grants.example.com')
        .intercept({ path: '/client' })
        .reply(200, JSON.stringify({
          client_id: 'https://filter-grants.example.com/client',
          redirect_uris: ['https://filter-grants.example.com/cb'],
          token_endpoint_auth_method: 'none',
          grant_types: ['authorization_code', 'urn:ietf:params:oauth:grant-type:device_code'],
        }), {
          headers: { 'content-type': 'application/json' },
        });

      return fixture6.agent.get('/auth')
        .query({
          client_id: 'https://filter-grants.example.com/client',
          redirect_uri: 'https://filter-grants.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(303)
        .expect((response) => {
          const location = new URL(response.headers.location, fixture6.provider.issuer);
          assert.match(location.pathname, /\/interaction\//);
        });
    });

    it('rejects when all grant_types are unsupported', { timeout: 3000 }, () => {
      mock('https://no-grants.example.com')
        .intercept({ path: '/client' })
        .reply(200, JSON.stringify({
          client_id: 'https://no-grants.example.com/client',
          redirect_uris: ['https://no-grants.example.com/cb'],
          token_endpoint_auth_method: 'none',
          grant_types: ['urn:ietf:params:oauth:grant-type:device_code'],
        }), {
          headers: { 'content-type': 'application/json' },
        });

      return fixture6.agent.get('/auth')
        .query({
          client_id: 'https://no-grants.example.com/client',
          redirect_uri: 'https://no-grants.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          assert.match(response.text, /invalid_client\b/);
        });
    });

    for (const [property, values] of [
      ['grant_types', []],
      ['response_types', ['unsupported']],
    ]) {
      it(`rejects ${property} with no supported values ${JSON.stringify(values)}`, { timeout: 3000 }, async () => {
        const provider = createProvider();
        const id = 'https://empty-intersection.example.com/client';
        mockMetadata(id, { [property]: values });

        await assert.rejects(resolve(provider, id), { error: 'invalid_client' });
      });
    }

    it('filters unsupported response_types and keeps supported ones', { timeout: 3000 }, () => {
      mock('https://filter-rt.example.com')
        .intercept({ path: '/client' })
        .reply(200, JSON.stringify({
          client_id: 'https://filter-rt.example.com/client',
          redirect_uris: ['https://filter-rt.example.com/cb'],
          token_endpoint_auth_method: 'none',
          grant_types: ['authorization_code'],
          response_types: ['code', 'code token id_token unsupported'],
        }), {
          headers: { 'content-type': 'application/json' },
        });

      return fixture6.agent.get('/auth')
        .query({
          client_id: 'https://filter-rt.example.com/client',
          redirect_uri: 'https://filter-rt.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(303)
        .expect((response) => {
          const location = new URL(response.headers.location, fixture6.provider.issuer);
          assert.match(location.pathname, /\/interaction\//);
        });
    });

    it('filters unsupported response_modes and keeps supported ones', { timeout: 3000 }, () => {
      mock('https://filter-rm.example.com')
        .intercept({ path: '/client' })
        .reply(200, JSON.stringify({
          client_id: 'https://filter-rm.example.com/client',
          redirect_uris: ['https://filter-rm.example.com/cb'],
          token_endpoint_auth_method: 'none',
          response_modes: ['query', 'unsupported_mode'],
        }), {
          headers: { 'content-type': 'application/json' },
        });

      return fixture6.agent.get('/auth')
        .query({
          client_id: 'https://filter-rm.example.com/client',
          redirect_uri: 'https://filter-rm.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(303)
        .expect((response) => {
          const location = new URL(response.headers.location, fixture6.provider.issuer);
          assert.match(location.pathname, /\/interaction\//);
        });
    });

    it('post-enum consistency validation still applies to filtered values', { timeout: 3000 }, () => {
      mock('https://consistency.example.com')
        .intercept({ path: '/client' })
        .reply(200, JSON.stringify({
          client_id: 'https://consistency.example.com/client',
          redirect_uris: ['https://consistency.example.com/cb'],
          token_endpoint_auth_method: 'none',
          grant_types: ['urn:ietf:params:oauth:grant-type:device_code', 'implicit'],
          response_types: ['id_token'],
        }), {
          headers: { 'content-type': 'application/json' },
        });

      // implicit is supported but device_code is not
      // after filtering grant_types becomes ['implicit'], response_types ['id_token'] is ok
      return fixture6.agent.get('/auth')
        .query({
          client_id: 'https://consistency.example.com/client',
          redirect_uri: 'https://consistency.example.com/cb',
          response_type: 'id_token',
          scope: 'openid',
          nonce: 'nonce',
        })
        .expect(303)
        .expect((response) => {
          const location = new URL(response.headers.location, fixture6.provider.issuer);
          assert.match(location.pathname, /\/interaction\//);
        });
    });
  });

  describe('allowFetch hook', () => {
    const fixture7 = Object.create(fixture);

    it('rejects when allowFetch returns false', { timeout: 3000 }, async () => {
      const { features } = i(fixture7.provider);
      const orig = features.clientIdMetadataDocument.allowFetch;
      features.clientIdMetadataDocument.allowFetch = async () => false;

      try {
        await fixture7.agent.get('/auth')
          .query({
            client_id: 'https://denied.example.com/client',
            redirect_uri: 'https://denied.example.com/cb',
            response_type: 'code',
            scope: 'openid',
          })
          .expect(400)
          .expect((response) => {
            assert.ok(response.text.includes('invalid_client'));
          });
      } finally {
        features.clientIdMetadataDocument.allowFetch = orig;
      }
    });
  });

  describe('allowClient hook', () => {
    const fixture8 = Object.create(fixture);

    it('rejects when allowClient returns false', { timeout: 3000 }, async () => {
      const { features } = i(fixture8.provider);
      const orig = features.clientIdMetadataDocument.allowClient;
      features.clientIdMetadataDocument.allowClient = async () => false;

      mock('https://denied-client.example.com')
        .intercept({ path: '/client' })
        .reply(200, JSON.stringify({
          client_id: 'https://denied-client.example.com/client',
          redirect_uris: ['https://denied-client.example.com/cb'],
          token_endpoint_auth_method: 'none',
        }), {
          headers: { 'content-type': 'application/json' },
        });

      try {
        await fixture8.agent.get('/auth')
          .query({
            client_id: 'https://denied-client.example.com/client',
            redirect_uri: 'https://denied-client.example.com/cb',
            response_type: 'code',
            scope: 'openid',
          })
          .expect(400)
          .expect((response) => {
            assert.ok(response.text.includes('invalid_client'));
          });
      } finally {
        features.clientIdMetadataDocument.allowClient = orig;
      }
    });
  });
});
