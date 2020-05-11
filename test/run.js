/* eslint-disable no-console */

const { createServer } = require('http');

const Mocha = require('mocha');
const { all: clearRequireCache } = require('clear-module');
const sample = require('lodash/sample');

const runtimeSupport = require('../lib/helpers/runtime_support');

const FORMAT_REGEXP = /^--format=([\w-]+)$/;
const formats = [];
process.argv.forEach((arg) => {
  if (FORMAT_REGEXP.test(arg)) {
    formats.push(RegExp.$1);
  }
});

if (!formats.length) {
  formats.push('opaque');
  formats.push('jwt');
  formats.push('jwt-ietf');
  if (runtimeSupport.EdDSA) {
    formats.push('paseto');
  }
  formats.push('dynamic');
}
const passed = [];

const { utils: { lookupFiles } } = Mocha;
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
  const jose = require('jose'); // eslint-disable-line global-require
  global.keystore = new jose.JWKS.KeyStore();
  await Promise.all([
    global.keystore.generate('RSA', 2048),
    global.keystore.generate('EC', 'P-256'),
    runtimeSupport.EdDSA ? global.keystore.generate('OKP', 'Ed25519') : undefined,
  ]);
  const DEFAULTS = require('../lib/helpers/defaults'); // eslint-disable-line global-require
  if (this.format === 'jwt-ietf' || typeof this.format === 'function') {
    DEFAULTS.features.ietfJWTAccessTokenProfile.enabled = true;
    DEFAULTS.features.ietfJWTAccessTokenProfile.ack = 2;
  }
  DEFAULTS.formats.AccessToken = this.format;
  DEFAULTS.formats.ClientCredentials = this.format;
  await new Promise((resolve) => {
    global.server = createServer().listen(0);
    global.server.once('listening', resolve);
  });
  await new Promise((resolve, reject) => {
    const mocha = new Mocha();
    mocha.files = files;

    if ('CI' in process.env) {
      mocha.reporter('min');
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
  if (formats.includes('opaque')) await run.call({ format: 'opaque' });
  if (formats.includes('jwt')) await run.call({ format: 'jwt' });
  if (formats.includes('jwt-ietf')) await run.call({ format: 'jwt-ietf' });
  if (formats.includes('paseto')) await run.call({ format: 'paseto' });
  if (formats.includes('dynamic')) await run.call({ format: () => sample(['opaque', 'jwt', 'jwt-ietf', runtimeSupport.EdDSA ? 'paseto' : undefined].filter(Boolean)) });
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
