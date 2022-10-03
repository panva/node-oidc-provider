/* eslint-disable no-console */

const { createServer } = require('http');

const Mocha = require('mocha');
const lookupFiles = require('mocha/lib/cli/lookup-files');
const { all: clearRequireCache } = require('clear-module');

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
  clearRequireCache();
  const jose = require('jose2'); // eslint-disable-line global-require
  global.keystore = new jose.JWKS.KeyStore();
  await Promise.all([
    global.keystore.generate('RSA', 2048),
    global.keystore.generate('EC', 'P-256'),
    global.keystore.generate('OKP', 'Ed25519'),
  ]);

  process.env.MOUNT_VIA = process.env.MOUNT_VIA || '';
  process.env.MOUNT_TO = process.env.MOUNT_TO || '/';

  const { MOUNT_VIA: via, MOUNT_TO: to } = process.env;

  await new Promise((resolve) => {
    global.server = createServer().listen(0, '::');
    global.server.once('listening', resolve);
  });
  await new Promise((resolve, reject) => {
    const mocha = new Mocha();
    mocha.timeout(3000);
    mocha.files = files;

    if ('CI' in process.env) {
      mocha.reporter('min');
      mocha.forbidOnly(); // force suite fail on encountered only test
      mocha.forbidPending(); // force suite fail on encountered skip test
    }

    const mountAddendum = via ? ` mounted using ${via === 'koa' ? 'koa-mount' : via} to ${to}` : '';
    console.log('\n\x1b[32m%s\x1b[0m', `Running suite${mountAddendum}`);

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

(async () => {
  await run();
  passed.forEach((pass) => console.log('\x1b[32m%s\x1b[0m', pass));
})()
  .catch((error) => {
    passed.forEach((pass) => console.log('\x1b[32m%s\x1b[0m', pass));
    if (error instanceof SuiteFailedError) {
      console.log('\x1b[31m%s\x1b[0m', error.message);
    } else {
      console.error(error);
    }
    global.server.close();
    process.exitCode = 1;
  });
