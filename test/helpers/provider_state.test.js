import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import Provider from '../../lib/index.js';
import instance, { get } from '../../lib/helpers/weak_cache.js';

function context(provider, {
  headers = {}, query = {}, body, contentType = 'application/x-www-form-urlencoded',
} = {}) {
  const ctx = {
    headers,
    query,
    is(type) { return body !== undefined && type === contentType; },
    get(name) { return headers[name.toLowerCase()] || ''; },
  };
  ctx.oidc = new provider.OIDCContext(ctx);
  ctx.oidc.body = body;
  return ctx.oidc;
}

describe('provider state access', () => {
  it('retains named and default accessors and isolated state for Provider subclasses', { timeout: 3000 }, () => {
    class CustomProvider extends Provider {}
    const first = new Provider('https://first.example.com');
    const second = new CustomProvider('https://second.example.com');

    assert.equal(get, instance);
    assert.equal(get(first), instance(first));
    assert.notEqual(instance(first), instance(second));
    assert.notEqual(instance(first).configuration, instance(second).configuration);
    assert.equal(Object.prototype.toString.call(instance(second).configuration), '[object Object]');

    const features = { ...instance(first).configuration.features };
    instance(first).configuration.features = features;
    assert.equal(instance(first).features, features);
    assert.notEqual(instance(second).features, features);
  });

  it('returns undefined for values that are not Provider instances', { timeout: 3000 }, () => {
    const provider = new Provider('https://op.example.com');
    const revoked = Proxy.revocable({}, {});
    revoked.revoke();

    for (const value of [
      undefined, null, false, 0, 0n, '', Symbol(), {}, [], () => {},
      Provider, Provider.prototype, Object.create(provider), new Proxy(provider, {}), revoked.proxy,
    ]) {
      assert.equal(instance(value), undefined);
    }
  });

  it('retains per-provider context identity and customizable own prototype descriptors', { timeout: 3000 }, () => {
    const first = new Provider('https://first.example.com');
    const second = new Provider('https://second.example.com');
    const oidc = context(first);

    assert.notEqual(first.OIDCContext, second.OIDCContext);
    assert.ok(oidc instanceof first.OIDCContext);
    assert.ok(!(oidc instanceof second.OIDCContext));
    assert.equal(oidc.provider, first);
    assert.equal(typeof Object.getOwnPropertyDescriptor(first.OIDCContext.prototype, 'acr').get, 'function');

    Object.defineProperty(first.OIDCContext.prototype, 'acr', { get() { return 'custom'; } });
    assert.equal(oidc.acr, 'custom');
    assert.notEqual(Object.getOwnPropertyDescriptor(second.OIDCContext.prototype, 'acr').get, Object.getOwnPropertyDescriptor(first.OIDCContext.prototype, 'acr').get);
  });

  it('reads replaced configuration and scopes from the owning provider', { timeout: 3000 }, () => {
    const first = new Provider('https://first.example.com');
    const second = new Provider('https://second.example.com');
    const firstContext = context(first);
    const secondContext = context(second);
    firstContext.params = secondContext.params = { scope: 'openid email profile' };

    instance(first).configuration = {
      ...instance(first).configuration,
      scopes: new Set(['email']),
    };
    instance(second).configuration.scopes = new Set(['profile']);

    assert.deepEqual(firstContext.requestParamOIDCScopes, new Set(['email']));
    assert.deepEqual(secondContext.requestParamOIDCScopes, new Set(['profile']));
  });

  it('reads the current FAPI callback while retaining the result for each request', { timeout: 3000 }, () => {
    const provider = new Provider('https://op.example.com');
    const first = context(provider);
    const second = context(provider);
    const client = {};
    first.entity('Client', client);
    const { configuration } = instance(provider);
    let calls = 0;
    configuration.features = {
      ...configuration.features,
      fapi: {
        ...configuration.features.fapi,
        profile(ctx, actualClient) {
          assert.equal(this, configuration.features.fapi);
          assert.equal(ctx, first.ctx);
          assert.equal(actualClient, client);
          calls += 1;
          return '2.0';
        },
      },
    };

    assert.equal(first.fapiProfile, '2.0');
    configuration.features.fapi.profile = () => '1.0 Final';
    assert.equal(first.fapiProfile, '2.0');
    assert.equal(second.fapiProfile, '1.0 Final');
    assert.equal(calls, 1);
  });

  it('reads supported claims at first use and retains parsed claims for that request', { timeout: 3000 }, () => {
    const provider = new Provider('https://op.example.com');
    const first = context(provider);
    const second = context(provider);
    first.params = second.params = {
      claims: JSON.stringify({ userinfo: { email: null, profile: null } }),
    };

    instance(provider).configuration.claimsSupported = new Set(['email']);
    assert.deepEqual(first.requestParamClaims, new Set(['email']));
    instance(provider).configuration.claimsSupported = new Set(['profile']);
    assert.deepEqual(first.requestParamClaims, new Set(['email']));
    assert.deepEqual(second.requestParamClaims, new Set(['profile']));
  });

  it('reads access-token query policy at invocation and retains an already parsed token', { timeout: 3000 }, () => {
    const provider = new Provider('https://op.example.com');
    const { configuration } = instance(provider);
    configuration.acceptQueryParamAccessTokens = false;
    const first = context(provider, { query: { access_token: 'first' } });
    configuration.acceptQueryParamAccessTokens = true;

    assert.equal(first.getAccessToken(), 'first');
    configuration.acceptQueryParamAccessTokens = false;
    assert.equal(first.getAccessToken(), 'first');
    assert.throws(() => context(provider, { query: { access_token: 'second' } }).getAccessToken(), {
      error_description: 'no access token provided',
    });

    configuration.acceptQueryParamAccessTokens = true;
    configuration.features.fapi = { ...configuration.features.fapi, enabled: true };
    assert.throws(() => context(provider, { query: { access_token: 'third' } }).getAccessToken(), {
      error_description: 'no access token provided',
    });
  });

  it('honors explicit query-token parsing options and retains already parsed tokens', { timeout: 3000 }, () => {
    const provider = new Provider('https://op.example.com');
    const first = context(provider, { query: { access_token: 'query-token' } });

    assert.equal(first.getAccessToken({ acceptQueryParam: true }), 'query-token');
    assert.equal(first.getAccessToken({ acceptQueryParam: false }), 'query-token');

    instance(provider).configuration.acceptQueryParamAccessTokens = true;
    assert.throws(() => context(provider, {
      query: { access_token: 'query-token' },
    }).getAccessToken({ acceptQueryParam: false }), {
      error_description: 'no access token provided',
    });
  });

  it('ignores query tokens alongside accepted header or body tokens', { timeout: 3000 }, () => {
    const provider = new Provider('https://op.example.com');
    const query = { access_token: 'ignored-query-token' };

    assert.equal(context(provider, {
      headers: { authorization: 'Bearer header-token' },
      query,
    }).getAccessToken({ acceptQueryParam: false }), 'header-token');

    assert.equal(context(provider, {
      body: { access_token: 'body-token' },
      query,
    }).getAccessToken({ acceptQueryParam: false }), 'body-token');

    assert.throws(() => context(provider, {
      headers: { authorization: 'Bearer header-token' },
      body: { access_token: 'body-token' },
      query,
    }).getAccessToken({ acceptQueryParam: false }), {
      error_description: 'access token must only be provided using one mechanism',
    });

    assert.throws(() => context(provider, {
      headers: { authorization: 'Bearer header-token' },
      query,
    }).getAccessToken({ acceptQueryParam: true }), {
      error_description: 'access token must only be provided using one mechanism',
    });
  });

  it('rejects repeated form body access tokens before choosing another mechanism', { timeout: 3000 }, () => {
    const provider = new Provider('https://op.example.com');

    for (const alternative of [
      {},
      { headers: { authorization: 'Bearer header-token' } },
      { query: { access_token: 'query-token' } },
    ]) {
      assert.throws(() => context(provider, {
        ...alternative,
        body: { access_token: ['first', 'second'] },
      }).getAccessToken({ acceptQueryParam: true }), {
        error_description: "'access_token' parameter must not be provided twice",
      });
    }
  });

  it('rejects repeated accepted query access tokens before choosing another mechanism', { timeout: 3000 }, () => {
    const provider = new Provider('https://op.example.com');

    for (const alternative of [
      {},
      { headers: { authorization: 'Bearer header-token' } },
      { body: { access_token: 'body-token' } },
    ]) {
      assert.throws(() => context(provider, {
        ...alternative,
        query: { access_token: ['first', 'second'] },
      }).getAccessToken({ acceptQueryParam: true }), {
        error_description: "'access_token' parameter must not be provided twice",
      });
    }
  });

  it('ignores repeated query access tokens when query tokens are not accepted', { timeout: 3000 }, () => {
    const provider = new Provider('https://op.example.com');
    const query = { access_token: ['first', 'second'] };

    assert.throws(() => context(provider, { query }).getAccessToken({ acceptQueryParam: false }), {
      error_description: 'no access token provided',
    });
    assert.equal(context(provider, {
      headers: { authorization: 'Bearer header-token' },
      query,
    }).getAccessToken({ acceptQueryParam: false }), 'header-token');
    assert.equal(context(provider, {
      body: { access_token: 'body-token' },
      query,
    }).getAccessToken({ acceptQueryParam: false }), 'body-token');
  });

  it('ignores access token arrays in non-form bodies', { timeout: 3000 }, () => {
    const provider = new Provider('https://op.example.com');
    const ignored = {
      body: { access_token: ['first', 'second'] },
      contentType: 'application/json',
    };

    assert.throws(() => context(provider, ignored).getAccessToken(), {
      error_description: 'no access token provided',
    });
    assert.equal(context(provider, {
      ...ignored,
      headers: { authorization: 'Bearer header-token' },
    }).getAccessToken(), 'header-token');
  });

  it('accepts one or more ASCII spaces after Bearer and DPoP schemes', { timeout: 3000 }, () => {
    const provider = new Provider('https://op.example.com');

    for (const scheme of ['bEaReR', 'dPoP']) {
      for (const spaces of [' ', '  ', '     ']) {
        const headers = { authorization: `${scheme}${spaces}token` };
        if (scheme === 'dPoP') headers.dpop = 'proof';

        assert.equal(context(provider, { headers }).getAccessToken({ acceptDPoP: true }), 'token');
      }
    }
  });

  it('does not treat other whitespace as authorization separators or merge credential parts', { timeout: 3000 }, () => {
    const provider = new Provider('https://op.example.com');

    for (const scheme of ['Bearer', 'DPoP']) {
      for (const suffix of ['\ttoken', '\u00a0token', '  first second']) {
        assert.throws(() => context(provider, {
          headers: { authorization: `${scheme}${suffix}`, dpop: 'proof' },
        }).getAccessToken({ acceptDPoP: true }), {
          error_description: 'invalid authorization header value format',
        });
      }
    }
  });

  it('reads a replaced DPoP feature configuration when parsing an access token', { timeout: 3000 }, () => {
    const provider = new Provider('https://op.example.com');
    const { configuration } = instance(provider);
    configuration.features.dPoP = { ...configuration.features.dPoP, enabled: false };
    const first = context(provider, { headers: { authorization: 'DPoP token', dpop: 'proof' } });

    configuration.features.dPoP = { ...configuration.features.dPoP, enabled: true };
    assert.equal(first.getAccessToken({ acceptDPoP: true }), 'token');

    configuration.features.dPoP = { ...configuration.features.dPoP, enabled: false };
    ((actual) => { assert.throws(actual, (error) => { assert.ok('error_description' in Object(error)); assert.equal(error.error_description, '`DPoP` header not provided'); return true; }); })(() => context(provider, {
      headers: { authorization: 'DPoP token', dpop: 'proof' },
    }).getAccessToken({ acceptDPoP: true }));
  });
});
