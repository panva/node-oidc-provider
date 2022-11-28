const getAuthorization = require('./authorization/index.js');
const userinfo = require('./userinfo.js');
const getToken = require('./token.js');
const jwks = require('./jwks.js');
const registration = require('./registration.js');
const getRevocation = require('./revocation.js');
const getIntrospection = require('./introspection.js');
const discovery = require('./discovery.js');
const endSession = require('./end_session.js');
const codeVerification = require('./code_verification.js');

module.exports = {
  getAuthorization,
  userinfo,
  getToken,
  jwks,
  registration,
  getRevocation,
  getIntrospection,
  discovery,
  endSession,
  codeVerification,
};
