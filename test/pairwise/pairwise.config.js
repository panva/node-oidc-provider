const { clone } = require('lodash');

const config = clone(require('../default.config'));

config.subjectTypes = ['public', 'pairwise'];

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    subject_type: 'pairwise',
    redirect_uris: ['https://client.example.com/cb'],
  },
};
