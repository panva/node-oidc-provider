import merge from 'lodash/merge.js';

import nanoid from '../../lib/helpers/nanoid.js';
import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, {
  registration: {
    enabled: true,
    idFactory() {
      return new URL(`https://repo.clients.com/path?id=${nanoid()}`).href;
    },
  },
  registrationManagement: {
    enabled: true,
  },
});

export default {
  config,
};
