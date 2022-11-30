import cloneDeep from 'lodash/cloneDeep.js';
import merge from 'lodash/merge.js';

import config from './ciba.config.js';

export default merge(cloneDeep(config), {
  config: { features: { requestObjects: { request: true, requestUri: true } } },
});
