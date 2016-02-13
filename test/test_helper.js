'use strict';

const { Provider } = require('../lib');
const path = require('path');
const { agent } = require('supertest');
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
  let config = require(conf);
  let provider = new Provider('http://localhost', { config });
  let server = provider.application.listen();
  let request = agent(server);

  provider.issuer = `http://localhost:${server.address().port}`;

  return { provider, request, server, config, responses };
};
