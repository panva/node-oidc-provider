/* eslint-disable no-console */

import { createServer } from 'node:http';
import { once } from 'node:events';
import { createRequire } from 'node:module';

import Mocha from 'mocha';
import clearRequireCache from 'clear-module';

const require = createRequire(import.meta.url);
const lookupFiles = require('mocha/lib/cli/lookup-files.js');

const passed = [];

const files = lookupFiles('test/**/*.test.js', ['js'], true);
class SuiteFailedError extends Error {}

const { info, warn } = console;
console.info = function (...args) {
  if (!args[0].includes('NOTICE: ')) info.apply(this, args);
};
console.warn = function (...args) {
  if (!args[0].includes('WARNING: ')) warn.apply(this, args);
};

async function run() {
  clearRequireCache.all();

  process.env.MOUNT_VIA = process.env.MOUNT_VIA || '';
  process.env.MOUNT_TO = process.env.MOUNT_TO || '/';

  const { MOUNT_VIA: via, MOUNT_TO: to } = process.env;

  global.server = createServer().listen(0, '::');
  await once(global.server, 'listening');
  const mocha = new Mocha();
  mocha.timeout(3000);
  mocha.files = files;
  await mocha.loadFilesAsync();

  if ('CI' in process.env) {
    mocha.reporter('min');
    mocha.forbidOnly(); // force suite fail on encountered only test
    mocha.forbidPending(); // force suite fail on encountered skip test
  }

  const mountAddendum = via ? ` mounted using ${via === 'koa' ? 'koa-mount' : via} to ${to}` : '';
  console.log('\n\x1b[32m%s\x1b[0m', `Running suite${mountAddendum}`);

  await new Promise((resolve, reject) => {
    mocha.run((failures) => {
      if (!failures) {
        passed.push(`Suite passed${mountAddendum}`);
        global.server.close(resolve);
      } else {
        reject(new SuiteFailedError(`Suite failed${mountAddendum}`));
      }
    });
  });
}

try {
  await run();
  passed.forEach((pass) => console.log('\x1b[32m%s\x1b[0m', pass));
} catch (error) {
  passed.forEach((pass) => console.log('\x1b[32m%s\x1b[0m', pass));
  if (error instanceof SuiteFailedError) {
    console.log('\x1b[31m%s\x1b[0m', error.message);
  } else {
    console.error(error);
  }
  global.server.close();
  process.exitCode = 1;
}
