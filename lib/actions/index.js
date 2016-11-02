'use strict';

const getAuthorization = require('./authorization');
const getUserinfo = require('./userinfo');
const getToken = require('./token');
const getCertificates = require('./certificates');
const getRegistration = require('./registration');
const getRevocation = require('./revocation');
const getIntrospection = require('./introspection');
const getWebfinger = require('./webfinger');
const getDiscovery = require('./discovery');
const getCheckSession = require('./check_session');
const getEndSession = require('./end_session');

module.exports = {
  getAuthorization,
  getUserinfo,
  getToken,
  getCertificates,
  getRegistration,
  getRevocation,
  getIntrospection,
  getWebfinger,
  getDiscovery,
  getCheckSession,
  getEndSession,
};
