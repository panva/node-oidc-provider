const getAuthorization = require('./authorization');
const userinfo = require('./userinfo');
const getToken = require('./token');
const certificates = require('./certificates');
const registration = require('./registration');
const getRevocation = require('./revocation');
const getIntrospection = require('./introspection');
const discovery = require('./discovery');
const checkSession = require('./check_session');
const endSession = require('./end_session');
const codeVerification = require('./code_verification');

module.exports = {
  getAuthorization,
  userinfo,
  getToken,
  certificates,
  registration,
  getRevocation,
  getIntrospection,
  discovery,
  checkSession,
  endSession,
  codeVerification,
};
