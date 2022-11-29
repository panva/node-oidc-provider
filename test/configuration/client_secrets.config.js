import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, {
  introspection: { enabled: true },
  revocation: { enabled: true },
  jwtIntrospection: { enabled: true },
});

export default {
  config,
};
