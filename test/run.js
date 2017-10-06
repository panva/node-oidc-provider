/* eslint-disable no-console */

const { JWK: { createKeyStore } } = require('node-jose');
const server = require('http').createServer().listen(0);
const Mocha = require('mocha');

const { utils: { lookupFiles } } = Mocha;
const mocha = new Mocha();
const NOOP = () => {};

server.once('listening', () => {
  global.server = server;
  global.keystore = createKeyStore();

  Promise.all([
    global.keystore.generate('RSA', 1024),
    global.keystore.generate('EC', 'P-256'),
  ])
    .then(() => {
      console.info = NOOP;
      process.on('unhandledRejection', NOOP);
      process.on('rejectionHandled', NOOP);

      mocha.files = lookupFiles('test/**/*.test.js', ['js'], true);

      mocha.run(process.exit);
    })
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
});
