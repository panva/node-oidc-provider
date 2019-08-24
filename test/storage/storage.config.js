const clone = require('lodash/clone');

const config = clone(require('../default.config'));

config.extraAccessTokenClaims = () => ({ foo: 'bar' });
config.features = {};
config.features.registration = {
  initialAccessToken: true,
  policies: {
    foo() {},
  },
};
config.subjectTypes = ['public', 'pairwise'];
config.pairwiseIdentifier = () => 'pairwise-sub';

module.exports = {
  config,
  clients: [
    {
      client_id: 'client',
      client_secret: 'secret',
      redirect_uris: ['https://client.example.com/cb'],
    },
    {
      client_id: 'pairwise',
      client_secret: 'secret',
      redirect_uris: ['https://client.example.com/cb'],
      subject_type: 'pairwise',
    },
  ],
};
