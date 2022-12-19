import cloneDeep from 'lodash/cloneDeep.js';

import config from './device_code.config.js';

const setup = cloneDeep(config);

setup.config.features.deviceFlow = {
  enabled: true,
  confirmParamName: 'approved',
};

export default setup;
