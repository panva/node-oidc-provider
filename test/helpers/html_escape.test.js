import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { defaults } from '../../lib/helpers/defaults.js';
import htmlSafe from '../../lib/helpers/html_safe.js';

describe('htmlSafe helper', () => {
  it('handles numbers', { timeout: 3000 }, () => {
    assert.deepEqual(htmlSafe(1), '1');
    assert.deepEqual(htmlSafe(1.1), '1.1');
  });

  it('handles non finites', { timeout: 3000 }, () => {
    assert.deepEqual(htmlSafe(NaN), '');
    assert.deepEqual(htmlSafe(Infinity), '');
    assert.deepEqual(htmlSafe(-Infinity), '');
  });

  it('handles strings', { timeout: 3000 }, () => {
    assert.deepEqual(htmlSafe('foobar&<>"\''), 'foobar&amp;&lt;&gt;&quot;&#39;');
    assert.deepEqual(htmlSafe(''), '');
  });

  it('handles booleans', { timeout: 3000 }, () => {
    assert.deepEqual(htmlSafe(false), 'false');
    assert.deepEqual(htmlSafe(true), 'true');
  });

  it('handles the rest', { timeout: 3000 }, () => {
    assert.deepEqual(htmlSafe(null), '');
    assert.deepEqual(htmlSafe(undefined), '');
  });
});

describe('default html rendering helpers', () => {
  const payload = '<img src=x onerror=alert(1)>';
  const escaped = '&lt;img src=x onerror=alert(1)&gt;';

  it('escapes device confirmation client display', { timeout: 3000 }, async () => {
    const ctx = {
      oidc: {
        client: {
          clientId: 'client',
          clientName: payload,
        },
      },
    };

    await defaults.features.deviceFlow.userCodeConfirmSource(ctx, '', ctx.oidc.client, undefined, 'ABCD-EFGH');

    assert.ok(!(ctx.body.includes(payload)));
    assert.ok(ctx.body.includes(`<strong>${escaped}</strong>`));
  });

  it('escapes device success client display', { timeout: 3000 }, async () => {
    const ctx = {
      oidc: {
        client: {
          clientId: 'client',
          clientName: payload,
        },
      },
    };

    await defaults.features.deviceFlow.successSource(ctx);

    assert.ok(!(ctx.body.includes(payload)));
    assert.ok(ctx.body.includes(`with ${escaped}`));
  });

  it('escapes post logout success client display', { timeout: 3000 }, async () => {
    const ctx = {
      oidc: {
        client: {
          clientId: 'client',
          clientName: payload,
        },
      },
    };

    await defaults.features.rpInitiatedLogout.postLogoutSuccessSource(ctx);

    assert.ok(!(ctx.body.includes(payload)));
    assert.ok(ctx.body.includes(`with ${escaped}`));
  });

  it('escapes logout host display', { timeout: 3000 }, async () => {
    const ctx = {
      host: payload,
    };

    await defaults.features.rpInitiatedLogout.logoutSource(ctx, '');

    assert.ok(!(ctx.body.includes(payload)));
    assert.ok(ctx.body.includes(`from ${escaped}?`));
  });
});
