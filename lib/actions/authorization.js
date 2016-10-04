'use strict';

const compose = require('koa-compose');

const bodyParser = require('../shared/conditional_body');
const rejectDupes = require('../shared/check_dupes');
const paramsMiddleware = require('../shared/get_params');

const PARAM_LIST = require('../consts/param_list');

const stack = require('./authorization/');

const parseBody = bodyParser('application/x-www-form-urlencoded');
const getParams = paramsMiddleware(PARAM_LIST);

module.exports = function authorizationAction(provider) {
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
    stack.checkScope(provider),
    stack.checkResponseType(provider),
    stack.checkRedirectUri,
    stack.checkPixy,
    stack.assignDefaults,
    stack.authorizationEmit(provider),
    stack.checkClaims(provider),
    stack.loadAccount(provider),
    stack.interactions(provider),
    stack.respond(provider),
    stack.processResponseTypes(provider),
  ]);
};
