'use strict';

const _ = require('lodash');
const config = _.clone(require('../default.config'));

config.subjectTypes = ['public', 'pairwise'];
config.pairwiseSalt = 'foobar';
config.features = { introspection: true };

module.exports = {
  config,
  clients: [{
    client_id: 'client',
    client_secret: 'secret',
    redirect_uris: ['https://client.example.com/cb'],
  }, {
    client_id: 'client-pairwise',
    client_secret: 'secret',
    subject_type: 'pairwise',
    redirect_uris: ['https://client.example.com/cb']
  }, {
    client_id: 'client-introspection',
    client_secret: 'secret',
    redirect_uris: [],
    response_types: [],
    grant_types: [],
  }]
};
