const PARAM_LIST = require('./param_list');
const DEV_KEYSTORE = require('./dev_keystore');
const CLIENT_ATTRIBUTES = require('./client_attributes');
const JWA = require('./jwa');

const PUSHED_REQUEST_URN = 'urn:ietf:params:oauth:request_uri:';

module.exports = {
  CLIENT_ATTRIBUTES,
  DEV_KEYSTORE,
  DYNAMIC_SCOPE_LABEL: Symbol('dynamic_scope_label'),
  JWA,
  PARAM_LIST,
  PUSHED_REQUEST_URN,
};
