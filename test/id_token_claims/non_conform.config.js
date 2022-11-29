import cloneDeep from 'lodash/cloneDeep.js';

import config from './conform.config.js';

const setup = cloneDeep(config);

setup.config.conformIdTokenClaims = false;

export default setup;
