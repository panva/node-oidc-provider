import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

config.extraTokenClaims = () => ({ foo: 'bar' });
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

export default {
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
