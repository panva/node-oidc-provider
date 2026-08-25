import { strict as assert } from 'node:assert';

import interactions from '../../lib/actions/authorization/interactions.js';
import { Check, Prompt } from '../../lib/helpers/interaction_policy/index.js';
import Provider from '../../lib/index.js';

function prompt(name, ...checks) {
  return new Prompt({ name }, ...checks);
}

describe('interaction policy collections', () => {
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
  });
});
