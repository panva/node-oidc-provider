const getAccessToken = require('./access_token');
const getAuthorizationCode = require('./authorization_code');
const getBaseModel = require('./base_model');
const getBaseToken = require('./base_token');
const getClient = require('./client');
const getClientCredentials = require('./client_credentials');
const getDeviceCode = require('./device_code');
const getIdToken = require('./id_token');
const getInitialAccessToken = require('./initial_access_token');
const getInteraction = require('./interaction');
const getPushedAuthorizationRequest = require('./pushed_authorization_request');
const getRefreshToken = require('./refresh_token');
const getRegistrationAccessToken = require('./registration_access_token');
const getReplayDetection = require('./replay_detection');
const getSession = require('./session');

module.exports = {
  getAccessToken,
  getAuthorizationCode,
  getBaseModel,
  getBaseToken,
  getClient,
  getClientCredentials,
  getDeviceCode,
  getIdToken,
  getInitialAccessToken,
  getInteraction,
  getPushedAuthorizationRequest,
  getRefreshToken,
  getRegistrationAccessToken,
  getReplayDetection,
  getSession,
};
