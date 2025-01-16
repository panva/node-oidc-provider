import merge from 'lodash/merge.js';

import getConfig from '../../default.config.js';

const config = getConfig();
merge(config, {
  httpOptions: (url) => {
    return url.pathname === '/with-custom-user-agent' ? { 'user-agent': 'some user agent' } : {};
  }
});

export default {
  config,
};
