import { expect } from 'chai';

import * as errors from '../../lib/helpers/errors.js';
import bootstrap from '../test_helper.js';

function expectCause(error, cause) {
  expect(error.cause).to.equal(cause);
  expect(Object.getOwnPropertyDescriptor(error, 'cause')).to.deep.equal({
    configurable: true,
    enumerable: false,
    value: cause,
    writable: true,
  });
}

function expectOwnDetail(error, detail) {
  expect(Object.hasOwn(error, 'error_detail')).to.be.true;
  expect(error.error_detail).to.equal(detail);
}

describe('error constructors', () => {
  const cause = new Error('underlying failure');

  it('preserves constructor arities', () => {
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
      expect(ErrorClass.length, ErrorClass.name).to.equal(arity);
    }
  });

  it('normalizes options in OIDCProviderError', () => {
    const legacy = new errors.OIDCProviderError(400, 'invalid_request', 'legacy detail');
    expectOwnDetail(legacy, 'legacy detail');

    const error = new errors.OIDCProviderError(500, 'server_error', { cause });

    expectCause(error, cause);
    expectOwnDetail(error, cause.message);
    expect(error).to.include({
      allow_redirect: true,
      error: 'server_error',
      expose: false,
      message: 'server_error',
      name: 'OIDCProviderError',
      status: 500,
      statusCode: 500,
    });

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
    expect(Object.hasOwn(nonError, 'error_detail')).to.be.false;

    const withoutCause = new errors.OIDCProviderError(400, 'invalid_request');
    expect(Object.hasOwn(withoutCause, 'cause')).to.be.false;
    expect(Object.hasOwn(withoutCause, 'error_detail')).to.be.false;
  });

  it('keeps the CustomOIDCProviderError signature compatible', () => {
    const legacy = new errors.CustomOIDCProviderError('custom_error', 'legacy description');
    expect(legacy.error_description).to.equal('legacy description');
    expect(Object.hasOwn(legacy, 'cause')).to.be.false;
    expect(Object.hasOwn(legacy, 'error_detail')).to.be.false;

    const caused = new errors.CustomOIDCProviderError('custom_error', 'description', { cause });
    expectCause(caused, cause);
    expectOwnDetail(caused, cause.message);

    const explicit = new errors.CustomOIDCProviderError('custom_error', 'description', {
      cause,
      detail: 'explicit detail',
    });
    expectOwnDetail(explicit, 'explicit detail');
  });

  it('supports strings and options in detail-only errors', () => {
    for (const ErrorClass of [errors.InvalidToken, errors.InvalidClientAuth, errors.InvalidGrant]) {
      const legacy = new ErrorClass('legacy detail');
      expectOwnDetail(legacy, 'legacy detail');
      expect(Object.hasOwn(legacy, 'cause'), ErrorClass.name).to.be.false;

      const caused = new ErrorClass({ cause });
      expectCause(caused, cause);
      expectOwnDetail(caused, cause.message);

      const explicit = new ErrorClass({ cause, detail: 'explicit detail' });
      expectOwnDetail(explicit, 'explicit detail');

      expectOwnDetail(new ErrorClass(), undefined);
    }
  });

  it('supports strings and options in InvalidClientMetadata', () => {
    const legacy = new errors.InvalidClientMetadata('metadata is invalid', 'legacy detail');
    expectOwnDetail(legacy, 'legacy detail');
    expect(Object.hasOwn(legacy, 'cause')).to.be.false;

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

  it('supports strings and options in scope errors', () => {
    for (const ErrorClass of [errors.InvalidScope, errors.InsufficientScope]) {
      const legacy = new ErrorClass('scope is invalid', 'openid', 'legacy detail');
      expectOwnDetail(legacy, 'legacy detail');
      expect(Object.hasOwn(legacy, 'cause'), ErrorClass.name).to.be.false;

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

  it('supports strings and options in InvalidRequest', () => {
    const legacy = new errors.InvalidRequest('request is invalid', 403, 'legacy detail');
    expectOwnDetail(legacy, 'legacy detail');
    expect(legacy.status).to.equal(403);
    expect(Object.hasOwn(legacy, 'cause')).to.be.false;

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

  it('supports strings and options in generated errors', () => {
    const legacy = new errors.AccessDenied('legacy description', 'legacy detail');
    expect(legacy.error_description).to.equal('legacy description');
    expectOwnDetail(legacy, 'legacy detail');
    expect(Object.hasOwn(legacy, 'cause')).to.be.false;

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
    expect(Object.hasOwn(nonError, 'error_detail')).to.be.false;

    expect(Object.hasOwn(new errors.AccessDenied(undefined, ''), 'error_detail')).to.be.false;
    expect(Object.hasOwn(new errors.AccessDenied(undefined, { detail: '' }), 'error_detail')).to.be.false;
  });

  it('adds options to InvalidRedirectUri without changing legacy calls', () => {
    const legacy = new errors.InvalidRedirectUri('ignored description', 'ignored detail');
    expect(legacy.error_description).to.equal('redirect_uri did not match any of the client\'s registered redirect_uris');
    expect(Object.hasOwn(legacy, 'cause')).to.be.false;
    expect(Object.hasOwn(legacy, 'error_detail')).to.be.false;

    const caused = new errors.InvalidRedirectUri({ cause });
    expectCause(caused, cause);
    expectOwnDetail(caused, cause.message);

    const explicit = new errors.InvalidRedirectUri({ cause, detail: 'explicit detail' });
    expectOwnDetail(explicit, 'explicit detail');
  });
});

describe('default error behavior', () => {
  before(bootstrap(import.meta.url));

  it('responds with json when no Accept header', function () {
    return this.agent.post('/me')
      .expect('content-type', /json/);
  });

  it('responds with json when */* header', function () {
    return this.agent.post('/me')
      .accept('*/*')
      .expect('content-type', /json/);
  });

  it('responds with html when browser like header', function () {
    return this.agent.post('/me')
      .accept('text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8')
      .expect('content-type', /html/);
  });
});
