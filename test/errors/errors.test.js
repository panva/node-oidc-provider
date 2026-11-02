import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';

import * as errors from '../../lib/helpers/errors.js';
import bootstrap from '../test_helper.js';

function expectCause(error, cause) {
  assert.equal(error.cause, cause);
  assert.deepEqual(Object.getOwnPropertyDescriptor(error, 'cause'), {
    configurable: true,
    enumerable: false,
    value: cause,
    writable: true,
  });
}

function expectOwnDetail(error, detail) {
  assert.equal(Object.hasOwn(error, 'error_detail'), true);
  assert.equal(error.error_detail, detail);
}

describe('error constructors', () => {
  const cause = new Error('underlying failure');

  it('preserves constructor arities', { timeout: 3000 }, () => {
    const arities = [
      [errors.OIDCProviderError, 2],
      [errors.CustomOIDCProviderError, 2],
      [errors.InvalidToken, 1],
      [errors.InvalidClientMetadata, 2],
      [errors.InvalidScope, 3],
      [errors.InsufficientScope, 3],
      [errors.InvalidRequest, 3],
      [errors.InvalidClientAuth, 1],
      [errors.InvalidGrant, 1],
      [errors.InvalidRedirectUri, 0],
      [errors.AccessDenied, 2],
    ];

    for (const [ErrorClass, arity] of arities) {
      assert.equal(ErrorClass.length, arity, ErrorClass.name);
    }
  });

  it('normalizes options in OIDCProviderError', { timeout: 3000 }, () => {
    const legacy = new errors.OIDCProviderError(400, 'invalid_request', 'legacy detail');
    expectOwnDetail(legacy, 'legacy detail');

    const error = new errors.OIDCProviderError(500, 'server_error', { cause });

    expectCause(error, cause);
    expectOwnDetail(error, cause.message);
    ((actual) => { assert.ok("allow_redirect" in Object(actual)); assert.equal(actual.allow_redirect, true); assert.ok("error" in Object(actual)); assert.equal(actual.error, 'server_error'); assert.ok("expose" in Object(actual)); assert.equal(actual.expose, false); assert.ok("message" in Object(actual)); assert.equal(actual.message, 'server_error'); assert.ok("name" in Object(actual)); assert.equal(actual.name, 'OIDCProviderError'); assert.ok("status" in Object(actual)); assert.equal(actual.status, 500); assert.ok("statusCode" in Object(actual)); assert.equal(actual.statusCode, 500); })(error);

    const explicit = new errors.OIDCProviderError(400, 'invalid_request', {
      cause,
      detail: 'explicit detail',
    });
    expectCause(explicit, cause);
    expectOwnDetail(explicit, 'explicit detail');

    const nonErrorCause = { reason: 'not an Error' };
    const nonError = new errors.OIDCProviderError(400, 'invalid_request', {
      cause: nonErrorCause,
    });
    expectCause(nonError, nonErrorCause);
    assert.equal(Object.hasOwn(nonError, 'error_detail'), false);

    const withoutCause = new errors.OIDCProviderError(400, 'invalid_request');
    assert.equal(Object.hasOwn(withoutCause, 'cause'), false);
    assert.equal(Object.hasOwn(withoutCause, 'error_detail'), false);
  });

  it('keeps the CustomOIDCProviderError signature compatible', { timeout: 3000 }, () => {
    const legacy = new errors.CustomOIDCProviderError('custom_error', 'legacy description');
    assert.equal(legacy.error_description, 'legacy description');
    assert.equal(Object.hasOwn(legacy, 'cause'), false);
    assert.equal(Object.hasOwn(legacy, 'error_detail'), false);

    const caused = new errors.CustomOIDCProviderError('custom_error', 'description', { cause });
    expectCause(caused, cause);
    expectOwnDetail(caused, cause.message);

    const explicit = new errors.CustomOIDCProviderError('custom_error', 'description', {
      cause,
      detail: 'explicit detail',
    });
    expectOwnDetail(explicit, 'explicit detail');
  });

  it('supports strings and options in detail-only errors', { timeout: 3000 }, () => {
    for (const ErrorClass of [errors.InvalidToken, errors.InvalidClientAuth, errors.InvalidGrant]) {
      const legacy = new ErrorClass('legacy detail');
      expectOwnDetail(legacy, 'legacy detail');
      assert.equal(Object.hasOwn(legacy, 'cause'), false, ErrorClass.name);

      const caused = new ErrorClass({ cause });
      expectCause(caused, cause);
      expectOwnDetail(caused, cause.message);

      const explicit = new ErrorClass({ cause, detail: 'explicit detail' });
      expectOwnDetail(explicit, 'explicit detail');

      expectOwnDetail(new ErrorClass(), undefined);
    }
  });

  it('supports strings and options in InvalidClientMetadata', { timeout: 3000 }, () => {
    const legacy = new errors.InvalidClientMetadata('metadata is invalid', 'legacy detail');
    expectOwnDetail(legacy, 'legacy detail');
    assert.equal(Object.hasOwn(legacy, 'cause'), false);

    const caused = new errors.InvalidClientMetadata('metadata is invalid', { cause });
    expectCause(caused, cause);
    expectOwnDetail(caused, cause.message);

    const explicit = new errors.InvalidClientMetadata('metadata is invalid', {
      cause,
      detail: 'explicit detail',
    });
    expectOwnDetail(explicit, 'explicit detail');
    expectOwnDetail(new errors.InvalidClientMetadata('metadata is invalid'), undefined);
  });

  it('supports strings and options in scope errors', { timeout: 3000 }, () => {
    for (const ErrorClass of [errors.InvalidScope, errors.InsufficientScope]) {
      const legacy = new ErrorClass('scope is invalid', 'openid', 'legacy detail');
      expectOwnDetail(legacy, 'legacy detail');
      assert.equal(Object.hasOwn(legacy, 'cause'), false, ErrorClass.name);

      const caused = new ErrorClass('scope is invalid', 'openid', { cause });
      expectCause(caused, cause);
      expectOwnDetail(caused, cause.message);

      const explicit = new ErrorClass('scope is invalid', 'openid', {
        cause,
        detail: 'explicit detail',
      });
      expectOwnDetail(explicit, 'explicit detail');
      expectOwnDetail(new ErrorClass('scope is invalid', 'openid'), undefined);
    }
  });

  it('supports strings and options in InvalidRequest', { timeout: 3000 }, () => {
    const legacy = new errors.InvalidRequest('request is invalid', 403, 'legacy detail');
    expectOwnDetail(legacy, 'legacy detail');
    assert.equal(legacy.status, 403);
    assert.equal(Object.hasOwn(legacy, 'cause'), false);

    const caused = new errors.InvalidRequest('request is invalid', undefined, { cause });
    expectCause(caused, cause);
    expectOwnDetail(caused, cause.message);

    const explicit = new errors.InvalidRequest('request is invalid', undefined, {
      cause,
      detail: 'explicit detail',
    });
    expectOwnDetail(explicit, 'explicit detail');
    expectOwnDetail(new errors.InvalidRequest('request is invalid'), undefined);
  });

  it('supports strings and options in generated errors', { timeout: 3000 }, () => {
    const legacy = new errors.AccessDenied('legacy description', 'legacy detail');
    assert.equal(legacy.error_description, 'legacy description');
    expectOwnDetail(legacy, 'legacy detail');
    assert.equal(Object.hasOwn(legacy, 'cause'), false);

    const caused = new errors.AccessDenied('description', { cause });
    expectCause(caused, cause);
    expectOwnDetail(caused, cause.message);

    const explicit = new errors.AccessDenied('description', {
      cause,
      detail: 'explicit detail',
    });
    expectOwnDetail(explicit, 'explicit detail');

    const nonErrorCause = 'not an Error';
    const nonError = new errors.AccessDenied(undefined, { cause: nonErrorCause });
    expectCause(nonError, nonErrorCause);
    assert.equal(Object.hasOwn(nonError, 'error_detail'), false);

    assert.equal(Object.hasOwn(new errors.AccessDenied(undefined, ''), 'error_detail'), false);
    assert.equal(Object.hasOwn(new errors.AccessDenied(undefined, { detail: '' }), 'error_detail'), false);
  });

  it('adds options to InvalidRedirectUri without changing legacy calls', { timeout: 3000 }, () => {
    const legacy = new errors.InvalidRedirectUri('ignored description', 'ignored detail');
    assert.equal(legacy.error_description, 'redirect_uri did not match any of the client\'s registered redirect_uris');
    assert.equal(Object.hasOwn(legacy, 'cause'), false);
    assert.equal(Object.hasOwn(legacy, 'error_detail'), false);

    const caused = new errors.InvalidRedirectUri({ cause });
    expectCause(caused, cause);
    expectOwnDetail(caused, cause.message);

    const explicit = new errors.InvalidRedirectUri({ cause, detail: 'explicit detail' });
    expectOwnDetail(explicit, 'explicit detail');
  });
});

describe('default error behavior', () => {
  const fixture1 = {};

  before(bootstrap(import.meta.url, fixture1), { timeout: 3000 });

  it('responds with json when no Accept header', { timeout: 3000 }, () => fixture1.agent.post('/me')
      .expect('content-type', /json/));

  it('responds with json when */* header', { timeout: 3000 }, () => fixture1.agent.post('/me')
      .accept('*/*')
      .expect('content-type', /json/));

  it('responds with html when browser like header', { timeout: 3000 }, () => fixture1.agent.post('/me')
      .accept('text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8')
      .expect('content-type', /html/));
});
