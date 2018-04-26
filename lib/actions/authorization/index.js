const checkClient = require('./check_client');
const checkResponseMode = require('./check_response_mode');
const throwNotSupported = require('./throw_not_supported');
const oauthRequired = require('./oauth_required');
const checkOpenidPresent = require('./check_openid_present');
const oneRedirectUriClients = require('./one_redirect_uri_clients');
const fetchRequestUri = require('./fetch_request_uri');
const decodeRequest = require('./decode_request');
const oidcRequired = require('./oidc_required');
const checkPrompt = require('./check_prompt');
const checkScope = require('./check_scope');
const checkResponseType = require('./check_response_type');
const checkRedirectUri = require('./check_redirect_uri');
const assignDefaults = require('./assign_defaults');
const checkClaims = require('./check_claims');
const loadAccount = require('./load_account');
const interactions = require('./interactions');
const respond = require('./respond');
const checkPixy = require('./check_pixy');
const processResponseTypes = require('./process_response_types');
const authorizationEmit = require('./authorization_emit');

const compose = require('koa-compose');

const bodyParser = require('../../shared/conditional_body');
const rejectDupes = require('../../shared/check_dupes');
const paramsMiddleware = require('../../shared/get_params');

const instance = require('../../helpers/weak_cache');

const { PARAM_LIST } = require('../../consts');

const parseBody = bodyParser('application/x-www-form-urlencoded');

module.exports = function authorizationAction(provider) {
  const whitelist = new Set(PARAM_LIST);
  const extras = instance(provider).configuration('extraParams');
  extras.forEach(whitelist.add.bind(whitelist));

  const getParams = paramsMiddleware(whitelist);

  return compose([
    parseBody,
    getParams,
    checkClient(provider),
    oneRedirectUriClients,
    rejectDupes,
    checkResponseMode(provider),
    throwNotSupported(provider),
    oauthRequired,
    checkOpenidPresent,
    fetchRequestUri(provider),
    decodeRequest(provider, whitelist),
    oidcRequired,
    checkPrompt(provider),
    checkResponseType(provider),
    checkScope(provider),
    checkRedirectUri,
    checkPixy(provider),
    assignDefaults,
    authorizationEmit(provider),
    checkClaims(provider),
    loadAccount(provider),
    interactions(provider),
    respond(provider),
    processResponseTypes(provider),
  ]);
};
