const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const config = cloneDeep(require('../default.config'));

config.extraAccessTokenClaims = () => ({ foo: 'bar' });
merge(config.features, {
  registration: {
    initialAccessToken: true,
    policies: {
      foo() {},
    },
  },
});
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
