/* eslint-disable no-console */

const { JWK: { createKeyStore } } = require('node-jose');
const server = require('http').createServer().listen(0);

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
      require('../node_modules/.bin/_mocha'); // eslint-disable-line global-require
    })
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
});
