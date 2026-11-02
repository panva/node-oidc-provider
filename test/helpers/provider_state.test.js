import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import Provider from '../../lib/index.js';
import instance, { get } from '../../lib/helpers/weak_cache.js';

function context(provider, { headers = {}, query = {} } = {}) {
  const ctx = {
    headers,
    query,
    is() { return false; },
    get(name) { return headers[name.toLowerCase()] || ''; },
  };
  ctx.oidc = new provider.OIDCContext(ctx);
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
    ((actual) => { assert.throws(actual, (error) => { assert.ok('error_description' in Object(error)); assert.equal(error.error_description, 'access tokens must not be provided via query parameter'); return true; }); })(() => context(provider, { query: { access_token: 'second' } }).getAccessToken());

    configuration.acceptQueryParamAccessTokens = true;
    configuration.features.fapi = { ...configuration.features.fapi, enabled: true };
    ((actual) => { assert.throws(actual, (error) => { assert.ok('error_description' in Object(error)); assert.equal(error.error_description, 'access tokens must not be provided via query parameter'); return true; }); })(() => context(provider, { query: { access_token: 'third' } }).getAccessToken());
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
