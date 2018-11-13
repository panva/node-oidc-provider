const noCache = require('../../shared/no_cache');
const bodyParser = require('../../shared/conditional_body');
const rejectDupes = require('../../shared/reject_dupes');
const paramsMiddleware = require('../../shared/assemble_params');
const sessionMiddleware = require('../../shared/session');
const instance = require('../../helpers/weak_cache');
const { PARAM_LIST } = require('../../consts');
const getCheckResourceFormat = require('../../shared/check_resource_format');

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
const checkWebMessageUri = require('./check_web_message_uri');
const assignDefaults = require('./assign_defaults');
const checkClaims = require('./check_claims');
const assignClaims = require('./assign_claims');
const loadAccount = require('./load_account');
const interactions = require('./interactions');
const respond = require('./respond');
const checkPixy = require('./check_pixy');
const processResponseTypes = require('./process_response_types');
const authorizationEmit = require('./authorization_emit');
const getResume = require('./resume');
const checkClientGrantType = require('./check_client_grant_type');
const deviceCheckParams = require('./device_check_params');
const deviceAuthorizationResponse = require('./device_authorization_response');
const deviceUserFlow = require('./device_user_flow');
const deviceUserFlowResponse = require('./device_user_flow_response');

const parseBody = bodyParser('application/x-www-form-urlencoded');

const A = 'authorization';
const R = 'resume';
const DA = 'device_authorization';
const CV = 'code_verification';
const DR = 'device_resume';

const clientIdSet = new Set(['client_id']);

module.exports = function authorizationAction(provider, endpoint) {
  const {
    features: {
      claimsParameter,
      resourceIndicators,
      pkce,
      webMessageResponseMode,
    },
    extraParams,
  } = instance(provider).configuration();

  const whitelist = new Set(PARAM_LIST);

  if (webMessageResponseMode) {
    whitelist.add('web_message_uri');
    whitelist.add('web_message_target');
  }

  if (pkce) {
    whitelist.add('code_challenge');
    whitelist.add('code_challenge_method');
  }

  if (claimsParameter) {
    whitelist.add('claims');
  }

  let rejectDupesMiddleware = rejectDupes;
  if (resourceIndicators) {
    whitelist.add('resource');
    rejectDupesMiddleware = rejectDupes.except.bind(undefined, new Set(['resource']));
  }

  extraParams.forEach(Set.prototype.add.bind(whitelist));
  if ([DA, CV, DR].includes(endpoint)) {
    whitelist.delete('response_type');
    whitelist.delete('response_mode');
    whitelist.delete('state');
    whitelist.delete('redirect_uri');
  }

  const stack = [];

  const use = (middleware, ...only) => {
    if (only.includes(endpoint)) {
      stack.push(middleware());
    }
  };
  const returnTo = /^(code|device)_/.test(endpoint) ? 'device_resume' : 'resume';

  /* eslint-disable no-multi-spaces, space-in-parens */
  use(() => noCache,                                      A, DA, R, CV, DR);
  use(() => sessionMiddleware(provider),                  A,     R,     DR);
  use(() => getResume(provider, whitelist, returnTo),            R,     DR);
  use(() => deviceUserFlow(provider, whitelist),                    CV, DR);
  use(() => parseBody,                                    A, DA           );
  use(() => paramsMiddleware(whitelist),                  A, DA           );
  use(() => rejectDupes.only(clientIdSet),                A, DA, R, CV, DR);
  use(() => checkClient(provider),                        A, DA, R, CV, DR);
  use(() => oneRedirectUriClients,                        A               );
  use(() => rejectDupesMiddleware,                        A, DA           );
  use(() => checkClientGrantType,                            DA           );
  use(() => checkResponseMode(provider),                  A               );
  use(() => throwNotSupported(provider),                  A, DA           );
  use(() => deviceCheckParams,                               DA           );
  use(() => oauthRequired,                                A               );
  use(() => checkOpenidPresent,                           A               );
  use(() => fetchRequestUri(provider),                    A, DA           );
  use(() => decodeRequest(provider, whitelist),           A, DA           );
  use(() => oidcRequired,                                 A               );
  use(() => checkPrompt(provider),                        A, DA           );
  use(() => checkResponseType(provider),                  A               );
  use(() => checkScope(provider, whitelist),              A, DA           );
  use(() => checkRedirectUri,                             A               );
  use(() => checkWebMessageUri(provider),                 A               );
  use(() => getCheckResourceFormat(provider),             A, DA           );
  use(() => checkPixy(provider),                          A, DA           );
  use(() => assignDefaults,                               A, DA           );
  use(() => checkClaims(provider),                        A, DA           );
  use(() => authorizationEmit(provider),                  A,     R, CV, DR);
  use(() => assignClaims(provider),                       A,     R, CV, DR);
  use(() => loadAccount(provider),                        A,     R, CV, DR);
  use(() => interactions(provider, returnTo),             A,     R, CV, DR);
  use(() => respond(provider),                            A,     R        );
  use(() => processResponseTypes(provider),               A,     R        );
  use(() => deviceAuthorizationResponse(provider),           DA           );
  use(() => deviceUserFlowResponse(provider),                       CV, DR);
  /* eslint-enable no-multi-spaces, space-in-parens */

  return stack;
};
