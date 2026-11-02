import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { it } from 'node:test';
import { promisify } from 'node:util';

import withTimeout from '../test/with_timeout.js';

it('returns the attempt result and propagates the original failure', async () => {
  assert.equal(await withTimeout(() => 'result', 1000), 'result');
  const failure = new Error('attempt failed');
  await assert.rejects(withTimeout(() => { throw failure; }, 1000), (error) => error === failure);
  await assert.rejects(withTimeout(() => Promise.reject(failure), 1000), (error) => error === failure);
});

it('rejects when an attempt does not settle before its deadline', async () => {
  await assert.rejects(withTimeout(() => new Promise(() => {}), 10), {
    message: 'test attempt timed out after 10ms',
  });
});

it('clears the deadline timer after both successful and failed attempts', async () => {
  const helper = new URL('../test/with_timeout.js', import.meta.url).href;
  await promisify(execFile)(process.execPath, ['--input-type=module', '-e', `
import withTimeout from ${JSON.stringify(helper)};
await withTimeout(() => 'result', 60000);
await withTimeout(() => { throw new Error('failure'); }, 60000).catch(() => {});
`], { timeout: 3000 });
});
