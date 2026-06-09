import { expect } from 'chai';

import { defaults } from '../../lib/helpers/defaults.js';
import htmlSafe from '../../lib/helpers/html_safe.js';

describe('htmlSafe helper', () => {
  it('handles numbers', () => {
    expect(htmlSafe(1)).to.eql('1');
    expect(htmlSafe(1.1)).to.eql('1.1');
  });

  it('handles non finites', () => {
    expect(htmlSafe(NaN)).to.eql('');
    expect(htmlSafe(Infinity)).to.eql('');
    expect(htmlSafe(-Infinity)).to.eql('');
  });

  it('handles strings', () => {
    expect(htmlSafe('foobar&<>"\'')).to.eql('foobar&amp;&lt;&gt;&quot;&#39;');
    expect(htmlSafe('')).to.eql('');
  });

  it('handles booleans', () => {
    expect(htmlSafe(false)).to.eql('false');
    expect(htmlSafe(true)).to.eql('true');
  });

  it('handles the rest', () => {
    expect(htmlSafe(null)).to.eql('');
    expect(htmlSafe(undefined)).to.eql('');
  });
});

describe('default html rendering helpers', () => {
  const payload = '<img src=x onerror=alert(1)>';
  const escaped = '&lt;img src=x onerror=alert(1)&gt;';

  it('escapes device confirmation client display', async () => {
    const ctx = {
      oidc: {
        client: {
          clientId: 'client',
          clientName: payload,
        },
      },
    };

    await defaults.features.deviceFlow.userCodeConfirmSource(ctx, '', ctx.oidc.client, undefined, 'ABCD-EFGH');

    expect(ctx.body).not.to.contain(payload);
    expect(ctx.body).to.contain(`<strong>${escaped}</strong>`);
  });

  it('escapes device success client display', async () => {
    const ctx = {
      oidc: {
        client: {
          clientId: 'client',
          clientName: payload,
        },
      },
    };

    await defaults.features.deviceFlow.successSource(ctx);

    expect(ctx.body).not.to.contain(payload);
    expect(ctx.body).to.contain(`with ${escaped}`);
  });

  it('escapes post logout success client display', async () => {
    const ctx = {
      oidc: {
        client: {
          clientId: 'client',
          clientName: payload,
        },
      },
    };

    await defaults.features.rpInitiatedLogout.postLogoutSuccessSource(ctx);

    expect(ctx.body).not.to.contain(payload);
    expect(ctx.body).to.contain(`with ${escaped}`);
  });

  it('escapes logout host display', async () => {
    const ctx = {
      host: payload,
    };

    await defaults.features.rpInitiatedLogout.logoutSource(ctx, '');

    expect(ctx.body).not.to.contain(payload);
    expect(ctx.body).to.contain(`from ${escaped}?`);
  });
});
