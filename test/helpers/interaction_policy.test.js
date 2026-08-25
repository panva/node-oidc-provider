import { strict as assert } from 'node:assert';

import { expect } from 'chai';

import interactions from '../../lib/actions/authorization/interactions.js';
import { base, Check, Prompt } from '../../lib/helpers/interaction_policy/index.js';
import Provider from '../../lib/index.js';

function prompt(name, ...checks) {
  return new Prompt({ name }, ...checks);
}

describe('interaction policy collections', () => {
  describe('prompts', () => {
    it('does not remove the final prompt when the requested name is absent', () => {
      const policy = base();

      policy.remove('missing');

      expect(policy.map(({ name }) => name)).to.eql(['login', 'consent']);
    });
  });

  describe('checks', () => {
    it('rejects non-Boolean check results with the configuration path', async () => {
      const custom = prompt(
        'custom',
        new Check('custom_reason', 'custom description', () => 'yes'),
      );
      const provider = new Provider('https://op.example.com', {
        interactions: { policy: [custom] },
      });

      await assert.rejects(
        interactions('resume', { oidc: { provider } }, () => {}),
        {
          name: 'TypeError',
          message: 'interactions.policy.custom.checks.custom_reason.check must return a Boolean',
        },
      );
    });

    it('does not remove the final check when the requested reason is absent', () => {
      const checks = base().get('login').checks;
      const reasons = checks.map(({ reason }) => reason);

      checks.remove('missing');

      expect(checks.map(({ reason }) => reason)).to.eql(reasons);
    });
  });
});
