import { describe, it } from 'node:test';
import assert from 'node:assert/strict';


import interactions from '../../lib/actions/authorization/interactions.js';
import { base, Check, Prompt } from '../../lib/helpers/interaction_policy/index.js';
import Provider from '../../lib/index.js';

function prompt(name, ...checks) {
  return new Prompt({ name }, ...checks);
}

describe('interaction policy collections', () => {
  describe('prompts', () => {
    it('does not remove the final prompt when the requested name is absent', { timeout: 3000 }, () => {
      const policy = base();

      policy.remove('missing');

      assert.deepEqual(policy.map(({ name }) => name), ['login', 'consent']);
    });
  });

  describe('checks', () => {
    it('rejects non-Boolean check results with the configuration path', { timeout: 3000 }, async () => {
      const custom = prompt(
        'custom',
        new Check('custom_reason', 'custom description', () => 'yes'),
      );
      const provider = new Provider('https://op.example.com', {
        interactions: { policy: [custom] },
      });

      await assert.rejects(
        interactions({ oidc: { provider, route: 'authorization' } }, () => {}),
        {
          name: 'TypeError',
          message: 'interactions.policy.custom.checks.custom_reason.check must return a Boolean',
        },
      );
    });

    it('does not remove the final check when the requested reason is absent', { timeout: 3000 }, () => {
      const checks = base().get('login').checks;
      const reasons = checks.map(({ reason }) => reason);

      checks.remove('missing');

      assert.deepEqual(checks.map(({ reason }) => reason), reasons);
    });
  });
});
