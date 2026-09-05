import { expect } from 'chai';

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
  it('retains named and default accessors and isolated state for Provider subclasses', () => {
    class CustomProvider extends Provider {}
    const first = new Provider('https://first.example.com');
    const second = new CustomProvider('https://second.example.com');

    expect(get).to.equal(instance);
    expect(get(first)).to.equal(instance(first));
    expect(instance(first)).not.to.equal(instance(second));
    expect(instance(first).configuration).not.to.equal(instance(second).configuration);
    expect(instance(second).configuration).to.be.an('object');

    const features = { ...instance(first).configuration.features };
    instance(first).configuration.features = features;
    expect(instance(first).features).to.equal(features);
    expect(instance(second).features).not.to.equal(features);
  });

  it('returns undefined for values that are not Provider instances', () => {
    const provider = new Provider('https://op.example.com');
    const revoked = Proxy.revocable({}, {});
    revoked.revoke();

    for (const value of [
      undefined, null, false, 0, 0n, '', Symbol(), {}, [], () => {},
      Provider, Provider.prototype, Object.create(provider), new Proxy(provider, {}), revoked.proxy,
    ]) {
      expect(instance(value)).to.equal(undefined);
    }
  });

  it('retains per-provider context identity and customizable own prototype descriptors', () => {
    const first = new Provider('https://first.example.com');
    const second = new Provider('https://second.example.com');
    const oidc = context(first);

    expect(first.OIDCContext).not.to.equal(second.OIDCContext);
    expect(oidc).to.be.instanceOf(first.OIDCContext);
    expect(oidc).not.to.be.instanceOf(second.OIDCContext);
    expect(oidc.provider).to.equal(first);
    expect(Object.getOwnPropertyDescriptor(first.OIDCContext.prototype, 'acr').get).to.be.a('function');

    Object.defineProperty(first.OIDCContext.prototype, 'acr', { get() { return 'custom'; } });
    expect(oidc.acr).to.equal('custom');
    expect(Object.getOwnPropertyDescriptor(second.OIDCContext.prototype, 'acr').get)
      .not.to.equal(Object.getOwnPropertyDescriptor(first.OIDCContext.prototype, 'acr').get);
  });

  it('reads replaced configuration and scopes from the owning provider', () => {
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

    expect(firstContext.requestParamOIDCScopes).to.eql(new Set(['email']));
    expect(secondContext.requestParamOIDCScopes).to.eql(new Set(['profile']));
  });

  it('reads the current FAPI callback while retaining the result for each request', () => {
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
          expect(this).to.equal(configuration.features.fapi);
          expect(ctx).to.equal(first.ctx);
          expect(actualClient).to.equal(client);
          calls += 1;
          return '2.0';
        },
      },
    };

    expect(first.fapiProfile).to.equal('2.0');
    configuration.features.fapi.profile = () => '1.0 Final';
    expect(first.fapiProfile).to.equal('2.0');
    expect(second.fapiProfile).to.equal('1.0 Final');
    expect(calls).to.equal(1);
  });

  it('reads supported claims at first use and retains parsed claims for that request', () => {
    const provider = new Provider('https://op.example.com');
    const first = context(provider);
    const second = context(provider);
    first.params = second.params = {
      claims: JSON.stringify({ userinfo: { email: null, profile: null } }),
    };

    instance(provider).configuration.claimsSupported = new Set(['email']);
    expect(first.requestParamClaims).to.eql(new Set(['email']));
    instance(provider).configuration.claimsSupported = new Set(['profile']);
    expect(first.requestParamClaims).to.eql(new Set(['email']));
    expect(second.requestParamClaims).to.eql(new Set(['profile']));
  });

  it('reads access-token query policy at invocation and retains an already parsed token', () => {
    const provider = new Provider('https://op.example.com');
    const { configuration } = instance(provider);
    configuration.acceptQueryParamAccessTokens = false;
    const first = context(provider, { query: { access_token: 'first' } });
    configuration.acceptQueryParamAccessTokens = true;

    expect(first.getAccessToken()).to.equal('first');
    configuration.acceptQueryParamAccessTokens = false;
    expect(first.getAccessToken()).to.equal('first');
    expect(() => context(provider, { query: { access_token: 'second' } }).getAccessToken())
      .to.throw().with.property('error_description', 'access tokens must not be provided via query parameter');

    configuration.acceptQueryParamAccessTokens = true;
    configuration.features.fapi = { ...configuration.features.fapi, enabled: true };
    expect(() => context(provider, { query: { access_token: 'third' } }).getAccessToken())
      .to.throw().with.property('error_description', 'access tokens must not be provided via query parameter');
  });

  it('reads a replaced DPoP feature configuration when parsing an access token', () => {
    const provider = new Provider('https://op.example.com');
    const { configuration } = instance(provider);
    configuration.features.dPoP = { ...configuration.features.dPoP, enabled: false };
    const first = context(provider, { headers: { authorization: 'DPoP token', dpop: 'proof' } });

    configuration.features.dPoP = { ...configuration.features.dPoP, enabled: true };
    expect(first.getAccessToken({ acceptDPoP: true })).to.equal('token');

    configuration.features.dPoP = { ...configuration.features.dPoP, enabled: false };
    expect(() => context(provider, {
      headers: { authorization: 'DPoP token', dpop: 'proof' },
    }).getAccessToken({ acceptDPoP: true }))
      .to.throw().with.property('error_description', '`DPoP` header not provided');
  });
});
