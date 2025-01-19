import merge from 'lodash/merge.js';

import getConfig from '../../default.config.js';

const config = getConfig();
merge(config, {
  httpOptions(url) {
    if (url.pathname === '/with-custom-user-agent') {
      return { 'user-agent': 'some user agent' };
    }

    return {};
  },
});

export default {
  config,
};
