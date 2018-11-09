/* eslint-disable no-console */

const { createServer } = require('http');

const { JWK: { createKeyStore } } = require('node-jose');
const Mocha = require('mocha');
const { all: clearRequireCache } = require('clear-module');
const { sample } = require('lodash');

const FORMAT_REGEXP = /^--format=(\w+)$/;
const formats = [];
process.argv.forEach((arg) => {
  if (FORMAT_REGEXP.test(arg)) {
    formats.push(RegExp.$1);
  }
});

if (!formats.length) {
  formats.push('opaque');
  formats.push('jwt');
  formats.push('dynamic');
  formats.push('legacy');
}
const passed = [];

const { utils: { lookupFiles } } = Mocha;
global.keystore = createKeyStore();
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
  const DEFAULTS = require('../lib/helpers/defaults'); // eslint-disable-line global-require
  DEFAULTS.formats.default = this.format;
  await new Promise((resolve) => {
    global.server = createServer().listen(0);
    global.server.once('listening', resolve);
  });
  await new Promise((resolve, reject) => {
    const mocha = new Mocha();
    mocha.files = files;

    if (process.env.CI) {
      mocha.retries(1); // retry flaky time comparison tests
      mocha.forbidOnly(); // force suite fail on encountered only test
      mocha.forbidPending(); // force suite fail on encountered skip test
    }

    mocha.run((failures) => {
      if (!failures) {
        passed.push(`Suite passed with ${typeof this.format === 'string' ? this.format : 'dynamic'} format`);
        global.server.close(resolve);
      } else {
        reject(new SuiteFailedError(`Suite failed with ${this.format} format`));
      }
    });
  });
}

(async () => {
  await Promise.all([
    global.keystore.generate('RSA', 1024),
    global.keystore.generate('EC', 'P-256'),
  ]);
  if (formats.includes('opaque')) await run.call({ format: 'opaque' });
  if (formats.includes('jwt')) await run.call({ format: 'jwt' });
  if (formats.includes('dynamic')) await run.call({ format: () => sample(['opaque', 'jwt']) });
  if (formats.includes('legacy')) await run.call({ format: 'legacy' });
  passed.forEach(pass => console.log('\x1b[32m%s\x1b[0m', pass));
})()
  .catch((error) => {
    passed.forEach(pass => console.log('\x1b[32m%s\x1b[0m', pass));
    if (error instanceof SuiteFailedError) {
      console.log('\x1b[31m%s\x1b[0m', error.message);
    } else {
      console.error(error);
    }
    global.server.close();
    process.exitCode = 1;
  });
