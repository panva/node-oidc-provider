'use strict';

const { agent } = require('supertest');
const { Provider } = require('../lib');
const path = require('path');
const _ = require('lodash');
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
    setupClients: function(passed) {
      const added = [];

      before(function(done) {
        let add = passed || clients;
        let promises = add.map(client => provider.Client.add(client).then((client) => {
          return added.push(client);
        }));
        Promise.all(promises).then(() => {
          done();
        }, done);
      });

      after(function() {
        added.forEach((client) => {
          provider.Client.remove(client.clientId);
        });
      });
    },
    setupCerts: function(passed) {
      const pre = _.pick(provider.configuration, [
        'requestObjectEncryptionAlgValuesSupported',
        'idTokenSigningAlgValuesSupported',
        'userinfoSigningAlgValuesSupported'
      ]);
      const added = [];

      before(function(done) {
        let add = passed || certs;
        let promises = add.map(cert => provider.addKey(cert).then((key) => {
          return added.push(key);
        }));
        Promise.all(promises).then(() => {
          done();
        }, done);
      });

      after(function() {
        _.assign(provider.configuration, pre);
        added.forEach(key => provider.keystore.remove(key));
      });
    }
  };
};
