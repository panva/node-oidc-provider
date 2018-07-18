/* eslint-disable camelcase */

const authorization_code = require('./authorization_code');
const client_credentials = require('./client_credentials');
const refresh_token = require('./refresh_token');
const device_code = require('./device_code');

module.exports = {
  authorization_code,
  client_credentials,
  refresh_token,
  'urn:ietf:params:oauth:grant-type:device_code': device_code,
};
