const getClient = require('./client');
const getIdToken = require('./id_token');
const getBaseToken = require('./base_token');
const getSession = require('./session');
const getAccessToken = require('./access_token');
const getAuthorizationCode = require('./authorization_code');
const getClientCredentials = require('./client_credentials');
const getRefreshToken = require('./refresh_token');
const getRegistrationAccessToken = require('./registration_access_token');
const getInitialAccessToken = require('./initial_access_token');

module.exports = {
  getAccessToken,
  getAuthorizationCode,
  getBaseToken,
  getClient,
  getClientCredentials,
  getIdToken,
  getInitialAccessToken,
  getRefreshToken,
  getRegistrationAccessToken,
  getSession,
};
