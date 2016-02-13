'use strict';

const { agent } = require('supertest');
const { Provider } = require('../lib');
const path = require('path');
const responses = {
  serverErrorBody: {
    error: 'server_error',
    error_description: 'oops something went wrong',
  }
};

module.exports = function(dir, basename) {
  let conf = path.format({
    dir,
    name: basename || path.basename(dir),
    ext: '.config.js'
  });
  let { config, certs, clients } = require(conf);
  let provider = new Provider('http://127.0.0.1', { config });
  let server = provider.app.listen();
  let request = agent(server);

  provider.issuer = `http://127.0.0.1:${server.address().port}`;

  return {
    provider, request, server, config, responses,
    setupCerts: function() {
      before(function(done) {
        Promise.all(certs.map(cert => provider.addKey(cert)))
          .then(() => done(), done);
      });
    }
  };
};
