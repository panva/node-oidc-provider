import { expect } from 'chai';

import bootstrap, { mock } from '../test_helper.js';
import { isValidClientIdUrl } from '../../lib/helpers/client_id_metadata_document.js';

const CLIENT_ID_URL = 'https://app.example.com/metadata';
const VALID_METADATA = {
  client_id: CLIENT_ID_URL,
  redirect_uris: ['https://app.example.com/cb'],
  token_endpoint_auth_method: 'none',
  client_name: 'Test App',
};

describe('Client ID Metadata Document', () => {
  before(bootstrap(import.meta.url));

  describe('isValidClientIdUrl', () => {
    it('accepts a valid HTTPS URL with a path', () => {
      expect(isValidClientIdUrl('https://example.com/client')).to.be.true;
    });

    it('accepts URLs with a port', () => {
      expect(isValidClientIdUrl('https://example.com:8443/client')).to.be.true;
    });

    it('accepts URLs with a query string', () => {
      expect(isValidClientIdUrl('https://example.com/client?id=123')).to.be.true;
    });

    it('rejects non-HTTPS URLs', () => {
      expect(isValidClientIdUrl('http://example.com/client')).to.be.false;
    });

    it('rejects URLs without a path component', () => {
      expect(isValidClientIdUrl('https://example.com')).to.be.false;
      expect(isValidClientIdUrl('https://example.com/')).to.be.false;
    });

    it('rejects URLs with single-dot path segments', () => {
      expect(isValidClientIdUrl('https://example.com/./client')).to.be.false;
    });

    it('rejects URLs with double-dot path segments', () => {
      expect(isValidClientIdUrl('https://example.com/../client')).to.be.false;
      expect(isValidClientIdUrl('https://example.com/a/../client')).to.be.false;
    });

    it('rejects URLs with a fragment', () => {
      expect(isValidClientIdUrl('https://example.com/client#frag')).to.be.false;
    });

    it('rejects URLs with a username', () => {
      expect(isValidClientIdUrl('https://user@example.com/client')).to.be.false;
    });

    it('rejects URLs with a password', () => {
      expect(isValidClientIdUrl('https://user:pass@example.com/client')).to.be.false;
    });

    it('rejects non-URL strings', () => {
      expect(isValidClientIdUrl('not-a-url')).to.be.false;
    });
  });

  describe('discovery', () => {
    it('includes client_id_metadata_document_supported', function () {
      return this.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('client_id_metadata_document_supported', true);
        });
    });
  });

  describe('client resolution via metadata document', () => {
    it('resolves a client from a valid metadata document', function () {
      mock('https://app.example.com')
        .intercept({ path: '/metadata' })
        .reply(200, JSON.stringify(VALID_METADATA), {
          headers: { 'content-type': 'application/json' },
        });

      return this.agent.get('/auth')
        .query({
          client_id: CLIENT_ID_URL,
          redirect_uri: 'https://app.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(303)
        .expect((response) => {
          const location = new URL(response.headers.location, this.provider.issuer);
          expect(location.pathname).to.match(/\/interaction\//);
        });
    });

    it('static/adapter clients take precedence over metadata document resolution', function () {
      return this.agent.get('/auth')
        .query({
          client_id: 'client',
          redirect_uri: 'https://client.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(303)
        .expect((response) => {
          const location = new URL(response.headers.location, this.provider.issuer);
          expect(location.pathname).to.match(/\/interaction\//);
        });
    });

    it('serves from cache on second request', async function () {
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
      await this.agent.get('/auth')
        .query({
          client_id: 'https://cached.example.com/client',
          redirect_uri: 'https://cached.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(303);

      // Second request - no additional mock needed, served from cache
      await this.agent.get('/auth')
        .query({
          client_id: 'https://cached.example.com/client',
          redirect_uri: 'https://cached.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(303);
    });

    it('rejects when metadata document has mismatched client_id', function () {
      mock('https://mismatch.example.com')
        .intercept({ path: '/client' })
        .reply(200, JSON.stringify({
          client_id: 'https://somewhere-else.example.com/client',
          redirect_uris: ['https://mismatch.example.com/cb'],
          token_endpoint_auth_method: 'none',
        }), {
          headers: { 'content-type': 'application/json' },
        });

      return this.agent.get('/auth')
        .query({
          client_id: 'https://mismatch.example.com/client',
          redirect_uri: 'https://mismatch.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          expect(response.text).to.contain('invalid_client_metadata');
        });
    });

    it('rejects when metadata document uses client_secret_basic', function () {
      mock('https://secretauth.example.com')
        .intercept({ path: '/client' })
        .reply(200, JSON.stringify({
          client_id: 'https://secretauth.example.com/client',
          redirect_uris: ['https://secretauth.example.com/cb'],
          token_endpoint_auth_method: 'client_secret_basic',
        }), {
          headers: { 'content-type': 'application/json' },
        });

      return this.agent.get('/auth')
        .query({
          client_id: 'https://secretauth.example.com/client',
          redirect_uri: 'https://secretauth.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          expect(response.text).to.contain('invalid_client_metadata');
        });
    });

    it('rejects when metadata document uses client_secret_post', function () {
      mock('https://secretpost.example.com')
        .intercept({ path: '/client' })
        .reply(200, JSON.stringify({
          client_id: 'https://secretpost.example.com/client',
          redirect_uris: ['https://secretpost.example.com/cb'],
          token_endpoint_auth_method: 'client_secret_post',
        }), {
          headers: { 'content-type': 'application/json' },
        });

      return this.agent.get('/auth')
        .query({
          client_id: 'https://secretpost.example.com/client',
          redirect_uri: 'https://secretpost.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          expect(response.text).to.contain('invalid_client_metadata');
        });
    });

    it('rejects when metadata document uses client_secret_jwt', function () {
      mock('https://secretjwt.example.com')
        .intercept({ path: '/client' })
        .reply(200, JSON.stringify({
          client_id: 'https://secretjwt.example.com/client',
          redirect_uris: ['https://secretjwt.example.com/cb'],
          token_endpoint_auth_method: 'client_secret_jwt',
        }), {
          headers: { 'content-type': 'application/json' },
        });

      return this.agent.get('/auth')
        .query({
          client_id: 'https://secretjwt.example.com/client',
          redirect_uri: 'https://secretjwt.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          expect(response.text).to.contain('invalid_client_metadata');
        });
    });

    it('rejects when metadata document contains client_secret', function () {
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

      return this.agent.get('/auth')
        .query({
          client_id: 'https://hassecret.example.com/client',
          redirect_uri: 'https://hassecret.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          expect(response.text).to.contain('invalid_client_metadata');
        });
    });

    it('rejects when fetch fails (network error)', function () {
      mock('https://fail.example.com')
        .intercept({ path: '/client' })
        .replyWithError(new Error('network error'));

      return this.agent.get('/auth')
        .query({
          client_id: 'https://fail.example.com/client',
          redirect_uri: 'https://fail.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          expect(response.text).to.contain('invalid_client');
        });
    });

    it('rejects when a URI property uses http instead of https', function () {
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

      return this.agent.get('/auth')
        .query({
          client_id: 'https://httpuri.example.com/client',
          redirect_uri: 'https://httpuri.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          expect(response.text).to.contain('invalid_client_metadata');
        });
    });

    it('rejects when logo_uri is not an https URI', function () {
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

      return this.agent.get('/auth')
        .query({
          client_id: 'https://badlogo.example.com/client',
          redirect_uri: 'https://badlogo.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          expect(response.text).to.contain('invalid_client_metadata');
        });
    });

    it('accepts metadata with https URI properties', function () {
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

      return this.agent.get('/auth')
        .query({
          client_id: 'https://gooduris.example.com/client',
          redirect_uri: 'https://gooduris.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(303)
        .expect((response) => {
          const location = new URL(response.headers.location, this.provider.issuer);
          expect(location.pathname).to.match(/\/interaction\//);
        });
    });

    it('rejects when response is not 200', function () {
      mock('https://notfound.example.com')
        .intercept({ path: '/client' })
        .reply(404, 'Not Found');

      return this.agent.get('/auth')
        .query({
          client_id: 'https://notfound.example.com/client',
          redirect_uri: 'https://notfound.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          expect(response.text).to.contain('invalid_client');
        });
    });

    it('rejects when the server responds with a redirect', function () {
      mock('https://redirect.example.com')
        .intercept({ path: '/client' })
        .reply(302, '', {
          headers: { location: 'https://redirect.example.com/other' },
        });

      return this.agent.get('/auth')
        .query({
          client_id: 'https://redirect.example.com/client',
          redirect_uri: 'https://redirect.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          expect(response.text).to.contain('invalid_client');
        });
    });

    it('rejects when response is not valid JSON', function () {
      mock('https://notjson.example.com')
        .intercept({ path: '/client' })
        .reply(200, 'this is not json', {
          headers: { 'content-type': 'application/json' },
        });

      return this.agent.get('/auth')
        .query({
          client_id: 'https://notjson.example.com/client',
          redirect_uri: 'https://notjson.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          expect(response.text).to.contain('invalid_client');
        });
    });

    it('rejects when response body exceeds maxResponseSize', function () {
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

      return this.agent.get('/auth')
        .query({
          client_id: 'https://large.example.com/client',
          redirect_uri: 'https://large.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          expect(response.text).to.contain('invalid_client');
        });
    });

    it('rejects early when Content-Length exceeds maxResponseSize', function () {
      mock('https://largecl.example.com')
        .intercept({ path: '/client' })
        .reply(200, '{}', {
          headers: {
            'content-type': 'application/json',
            'content-length': '999999',
          },
        });

      return this.agent.get('/auth')
        .query({
          client_id: 'https://largecl.example.com/client',
          redirect_uri: 'https://largecl.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          expect(response.text).to.contain('invalid_client');
        });
    });

    it('does not resolve non-URL client_id values', function () {
      return this.agent.get('/auth')
        .query({
          client_id: 'nonexistent-client',
          redirect_uri: 'https://client.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          expect(response.text).to.contain('invalid_client');
        });
    });

    it('does not resolve HTTP (non-HTTPS) client_id URLs', function () {
      return this.agent.get('/auth')
        .query({
          client_id: 'http://app.example.com/client',
          redirect_uri: 'https://app.example.com/cb',
          response_type: 'code',
          scope: 'openid',
        })
        .expect(400)
        .expect((response) => {
          expect(response.text).to.contain('invalid_client');
        });
    });
  });

  describe('allowFetch hook', () => {
    it('rejects when allowFetch returns false', async function () {
      const { features } = i(this.provider); // eslint-disable-line no-undef
      const orig = features.clientIdMetadataDocument.allowFetch;
      features.clientIdMetadataDocument.allowFetch = async () => false;

      try {
        await this.agent.get('/auth')
          .query({
            client_id: 'https://denied.example.com/client',
            redirect_uri: 'https://denied.example.com/cb',
            response_type: 'code',
            scope: 'openid',
          })
          .expect(400)
          .expect((response) => {
            expect(response.text).to.contain('invalid_client');
          });
      } finally {
        features.clientIdMetadataDocument.allowFetch = orig;
      }
    });
  });

  describe('allowClient hook', () => {
    it('rejects when allowClient returns false', async function () {
      const { features } = i(this.provider); // eslint-disable-line no-undef
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
        await this.agent.get('/auth')
          .query({
            client_id: 'https://denied-client.example.com/client',
            redirect_uri: 'https://denied-client.example.com/cb',
            response_type: 'code',
            scope: 'openid',
          })
          .expect(400)
          .expect((response) => {
            expect(response.text).to.contain('invalid_client');
          });
      } finally {
        features.clientIdMetadataDocument.allowClient = orig;
      }
    });
  });
});
