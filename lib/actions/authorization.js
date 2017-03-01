'use strict';

const compose = require('koa-compose');

const bodyParser = require('../shared/conditional_body');
const rejectDupes = require('../shared/check_dupes');
const paramsMiddleware = require('../shared/get_params');

const instance = require('../helpers/weak_cache');

const PARAM_LIST = require('../consts').PARAM_LIST;

const stack = require('./authorization/');

const parseBody = bodyParser('application/x-www-form-urlencoded');

module.exports = function authorizationAction(provider) {
  const whitelist = new Set(PARAM_LIST);
  const extras = instance(provider).configuration('extraParams');
  extras.forEach(whitelist.add.bind(whitelist));

  const getParams = paramsMiddleware(whitelist);

  return compose([
    parseBody,
    getParams,
    stack.checkClient(provider),
    rejectDupes,
    stack.checkResponseMode,
    stack.throwNotSupported(provider),
    stack.oauthRequired,
    stack.checkOpenidPresent,
    stack.noRedirectUriClients,
    stack.fetchRequestUri(provider),
    stack.decodeRequest(provider),
    stack.oidcRequired,
    stack.checkPrompt(provider),
    stack.checkResponseType(provider),
    stack.checkScope(provider),
    stack.checkRedirectUri,
    stack.checkPixy(provider),
    stack.assignDefaults,
    stack.authorizationEmit(provider),
    stack.checkClaims(provider),
    stack.loadAccount(provider),
    stack.interactions(provider),
    stack.respond(provider),
    stack.processResponseTypes(provider),
  ]);
};
