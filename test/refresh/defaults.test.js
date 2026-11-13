import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import Provider from '../../lib/index.js';
import als from '../../lib/helpers/als.js';
import getDefaults from '../../lib/helpers/defaults.js';

const YEAR = 365.25 * 24 * 60 * 60;
const FORTNIGHT = 14 * 24 * 60 * 60;
const defaults = getDefaults();

function token({ lifetime = 0, remainingTTL = 3600, senderConstrained = false, percentage = 0 } = {}) {
  return {
    exp: 1700000000 + remainingTTL,
    remainingTTL,
    totalLifetime: () => lifetime,
    isSenderConstrained: () => senderConstrained,
    ttlPercentagePassed: () => percentage,
  };
}

function context(refreshToken, client) {
  return { oidc: { entities: { Client: client, RefreshToken: refreshToken, RotatedRefreshToken: refreshToken } } };
}

describe('default refresh token policies', () => {
  for (const lifetime of [YEAR - 1, YEAR, YEAR + 1]) {
    it(`rotates public unbound tokens at chain age ${lifetime}`, { timeout: 3000 }, () => {
      const client = { applicationType: 'native', clientAuthMethod: 'none' };
      const refreshToken = token({ lifetime });

      assert.equal(defaults.rotateRefreshToken(context(refreshToken, client)), true);
    });
  }

  for (const senderConstrained of [false, true]) {
    it(`preserves public web token expiration with sender constraint ${senderConstrained}`, { timeout: 3000 }, () => {
      const client = { applicationType: 'web', clientAuthMethod: 'none' };
      const previous = token({ senderConstrained, remainingTTL: 1234 });
      const rotated = token({ senderConstrained });

      assert.equal(defaults.ttl.RefreshToken(context(previous, client), rotated, client), 1234);
      assert.equal(rotated.exp, previous.exp);
    });
  }

  for (const lifetime of [YEAR, YEAR + 1]) {
    it(`keeps native public tokens rotating without extending expiration at chain age ${lifetime}`, { timeout: 3000 }, () => {
      const client = { applicationType: 'native', clientAuthMethod: 'none' };
      const previous = token({ lifetime, remainingTTL: 1234 });
      const ctx = context(previous, client);

      assert.equal(defaults.rotateRefreshToken(ctx), true);
      assert.equal(defaults.ttl.RefreshToken(ctx, token(), client), 1234);
    });
  }

  it('allows native public token lifetimes to slide before the one-year cutoff', { timeout: 3000 }, () => {
    const client = { applicationType: 'native', clientAuthMethod: 'none' };
    const previous = token({ lifetime: YEAR - 1 });

    assert.equal(defaults.ttl.RefreshToken(context(previous, client), token(), client), FORTNIGHT);
  });

  for (const clientAuthMethod of ['none', 'private_key_jwt']) {
    it(`stops rotating other tokens at one year with authentication ${clientAuthMethod}`, { timeout: 3000 }, () => {
      const client = { applicationType: 'native', clientAuthMethod };
      const previous = token({ lifetime: YEAR, senderConstrained: true, percentage: 100 });

      assert.equal(defaults.rotateRefreshToken(context(previous, client)), false);
    });
  }

  it('preserves expiration when a custom policy rotates confidential tokens after one year', { timeout: 3000 }, () => {
    const client = { applicationType: 'web', clientAuthMethod: 'private_key_jwt' };
    const previous = token({ lifetime: YEAR, remainingTTL: 1234 });

    assert.equal(defaults.ttl.RefreshToken(context(previous, client), token(), client), 1234);
  });

  it('uses the initial lifetime when issuing a fresh token', { timeout: 3000 }, () => {
    const client = { applicationType: 'web', clientAuthMethod: 'none' };

    assert.equal(defaults.ttl.RefreshToken(undefined, token(), client), FORTNIGHT);
  });

  it('preserves the absolute expiration when serialization follows TTL evaluation', { timeout: 3000 }, async (t) => {
    let now = 1700000000000;
    t.mock.method(Date, 'now', () => now);
    const provider = new Provider('https://op.example.com', {
      features: { devInteractions: { enabled: false } },
    });
    const client = { clientId: 'browser', applicationType: 'web', clientAuthMethod: 'none' };
    const previous = new provider.RefreshToken({ client, iat: now / 1000, exp: now / 1000 + 3600 });
    const rotated = new provider.RefreshToken({ client });

    await als.run(context(previous, client), async () => {
      assert.equal(rotated.expiration, 3600);
      now += 2000;

      const { payload } = await rotated.getValueAndPayload();
      assert.equal(payload.exp, previous.exp);
    });
  });
});
