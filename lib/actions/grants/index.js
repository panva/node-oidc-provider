/* eslint-disable camelcase */

const authorization_code = require('./authorization_code.js');
const client_credentials = require('./client_credentials.js');
const refresh_token = require('./refresh_token.js');
const device_code = require('./device_code.js');
const ciba = require('./ciba.js');

module.exports = {
  authorization_code,
  client_credentials,
  refresh_token,
  'urn:ietf:params:oauth:grant-type:device_code': device_code,
  'urn:openid:params:grant-type:ciba': ciba,
};
