import { run } from 'node:test';
import { spec } from 'node:test/reporters';
import { fileURLToPath } from 'node:url';

import assertNoFocusedTests from '../tools/check-test-focus.js';
import testFiles from './files.js';

process.env.MOUNT_VIA ||= '';
process.env.MOUNT_TO ||= '/';

const { MOUNT_VIA: via, MOUNT_TO: to } = process.env;
const mountAddendum = via ? ` mounted using ${via === 'koa' ? 'koa-mount' : via} to ${to}` : '';
console.log('\n\x1b[32m%s\x1b[0m', `Running suite${mountAddendum}`);

try {
  if ('CI' in process.env) {
    assertNoFocusedTests([
      ...testFiles(),
      fileURLToPath(new URL('./suite.js', import.meta.url)),
      fileURLToPath(new URL('./test_helper.js', import.meta.url)),
    ]);
  }
  const tests = run({
    files: [fileURLToPath(new URL('./suite.js', import.meta.url))],
    concurrency: 1,
  });
  let failed = false;
  tests.on('test:fail', () => { failed = true; });
  for await (const output of tests.compose(spec)) process.stdout.write(output);
  if (failed) {
    process.exitCode = 1;
    console.log('\x1b[31m%s\x1b[0m', `Suite failed${mountAddendum}`);
  } else {
    console.log('\x1b[32m%s\x1b[0m', `Suite passed${mountAddendum}`);
  }
} catch (error) {
  console.error(error);
  process.exitCode = 1;
}
