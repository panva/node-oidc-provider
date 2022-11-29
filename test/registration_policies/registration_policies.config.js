import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, {
  registrationManagement: { enabled: true, rotateRegistrationAccessToken: false },
  registration: {
    enabled: true,
    initialAccessToken: true,
    policies: {
      'empty-policy': () => {},
    },
  },
});

export default {
  config,
};
