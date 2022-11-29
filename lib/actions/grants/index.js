/* eslint-disable camelcase */

import * as authorization_code from './authorization_code.js';
import * as client_credentials from './client_credentials.js';
import * as refresh_token from './refresh_token.js';
import * as device_code from './device_code.js';
import * as ciba from './ciba.js';

export default {
  authorization_code,
  client_credentials,
  refresh_token,
  'urn:ietf:params:oauth:grant-type:device_code': device_code,
  'urn:openid:params:grant-type:ciba': ciba,
};
