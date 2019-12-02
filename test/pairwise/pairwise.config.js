const cloneDeep = require('lodash/cloneDeep');

const config = cloneDeep(require('../default.config'));

config.subjectTypes = ['public', 'pairwise'];

module.exports = {
  config,
  clients: [{
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    subject_type: 'pairwise',
    redirect_uris: ['https://client.example.com/cb'],
  }, {
    client_id: 'client-static-with-sector',
    client_secret: 'secret',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    subject_type: 'pairwise',
    redirect_uris: ['https://client.example.com/cb'],
    sector_identifier_uri: 'https://foobar.example.com/file_of_redirect_uris',
  }],
};
