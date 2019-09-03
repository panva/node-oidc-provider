const noCache = require('../../shared/no_cache');
const bodyParser = require('../../shared/conditional_body');
const rejectDupes = require('../../shared/reject_dupes');
const paramsMiddleware = require('../../shared/assemble_params');
const sessionMiddleware = require('../../shared/session');
const instance = require('../../helpers/weak_cache');
const { PARAM_LIST } = require('../../consts');
const checkResource = require('../../shared/check_resource');
const getTokenAuth = require('../../shared/token_auth');

const checkClient = require('./check_client');
const checkResponseMode = require('./check_response_mode');
const rejectUnsupported = require('./reject_unsupported');
const rejectRegistration = require('./reject_registration');
const oauthRequired = require('./oauth_required');
const oneRedirectUriClients = require('./one_redirect_uri_clients');
const fetchRequestUri = require('./fetch_request_uri');
const processRequestObject = require('./process_request_object');
const oidcRequired = require('./oidc_required');
const checkPrompt = require('./check_prompt');
const checkMaxAge = require('./check_max_age');
const checkIdTokenHint = require('./check_id_token_hint');
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
const checkPKCE = require('./check_pkce');
const processResponseTypes = require('./process_response_types');
const authorizationEmit = require('./authorization_emit');
const getResume = require('./resume');
const checkClientGrantType = require('./check_client_grant_type');
const checkOpenidScope = require('./check_openid_scope');
const deviceAuthorizationResponse = require('./device_authorization_response');
const deviceAuthorizationClientId = require('./device_authorization_client_id');
const deviceUserFlow = require('./device_user_flow');
const deviceUserFlowResponse = require('./device_user_flow_response');
const requestObjectRemapErrors = require('./request_object_remap_errors');
const requestObjectEndpointParameters = require('./request_object_endpoint_params');
const requestObjectResponse = require('./request_object_response');

const A = 'authorization';
const R = 'resume';
const DA = 'device_authorization';
const CV = 'code_verification';
const DR = 'device_resume';
const RO = 'request_object';

const authRequired = new Set([DA, RO]);

const parseBody = bodyParser.bind(undefined, 'application/x-www-form-urlencoded');

module.exports = function authorizationAction(provider, endpoint) {
  const {
    features: {
      claimsParameter,
      resourceIndicators,
      webMessageResponseMode,
    },
    extraParams,
  } = instance(provider).configuration();

  const whitelist = new Set(PARAM_LIST);

  if (webMessageResponseMode.enabled) {
    whitelist.add('web_message_uri');
    whitelist.add('web_message_target');
  }

  if (claimsParameter.enabled) {
    whitelist.add('claims');
  }

  let rejectDupesMiddleware = rejectDupes.bind(undefined, {});
  if (resourceIndicators.enabled) {
    whitelist.add('resource');
    rejectDupesMiddleware = rejectDupes.bind(undefined, { except: new Set(['resource']) });
  }

  extraParams.forEach(Set.prototype.add.bind(whitelist));
  if ([DA, CV, DR].includes(endpoint)) {
    whitelist.delete('web_message_uri');
    whitelist.delete('web_message_target');
    whitelist.delete('response_type');
    whitelist.delete('response_mode');
    whitelist.delete('code_challenge_method');
    whitelist.delete('code_challenge');
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
  use(() => noCache,                                        A, DA, R, CV, DR, RO);
  use(() => sessionMiddleware,                              A,     R,     DR    );
  use(() => deviceUserFlow.bind(undefined, whitelist),         CV,        DR    );
  use(() => getResume.bind(undefined, whitelist, returnTo), R,            DR    );
  use(() => parseBody,                                      A, DA,            RO);
  if (authRequired.has(endpoint)) {
    const { params: authParams, middleware: tokenAuth } = getTokenAuth(provider, 'token', endpoint);
    use(() => paramsMiddleware.bind(undefined, authParams),    DA,            RO);
    tokenAuth.forEach((tokenAuthMiddleware) => {
      use(() => tokenAuthMiddleware,                           DA,            RO);
    });
  }
  use(() => deviceAuthorizationClientId,                       DA               );
  use(() => paramsMiddleware.bind(undefined, whitelist),    A, DA,            RO);
  use(() => requestObjectEndpointParameters,                                  RO);
  use(() => rejectDupesMiddleware,                          A, DA,            RO);
  use(() => rejectUnsupported,                              A, DA               );
  use(() => checkClient,                                    A, DA, R, CV, DR    );
  use(() => checkClientGrantType,                              DA               );
  use(() => checkResponseMode,                              A                   );
  use(() => fetchRequestUri,                                A, DA               );
  use(() => requestObjectRemapErrors,                                         RO);
  use(() => processRequestObject.bind(
    undefined, whitelist, rejectDupesMiddleware,
  ),                                                        A, DA,            RO);
  use(() => oneRedirectUriClients,                          A,                RO);
  use(() => oauthRequired,                                  A,                RO);
  use(() => rejectRegistration,                             A, DA,            RO);
  use(() => oidcRequired,                                   A,                RO);
  use(() => assignDefaults,                                 A, DA               );
  use(() => checkOpenidScope.bind(undefined, whitelist),    A, DA,            RO);
  use(() => checkPrompt,                                    A, DA,            RO);
  use(() => checkResponseType,                              A,                RO);
  use(() => checkScope.bind(undefined, whitelist),          A, DA,            RO);
  use(() => checkRedirectUri,                               A,                RO);
  use(() => checkWebMessageUri,                             A,                RO);
  use(() => checkResource,                                  A, DA,            RO);
  use(() => checkPKCE,                                      A, DA,            RO);
  use(() => checkClaims,                                    A, DA,            RO);
  use(() => checkMaxAge,                                    A, DA,            RO);
  use(() => checkIdTokenHint,                               A, DA,            RO);
  use(() => authorizationEmit,                              A,     R, CV, DR    );
  use(() => assignClaims,                                   A,     R, CV, DR    );
  use(() => loadAccount,                                    A,     R, CV, DR    );
  use(() => interactions.bind(undefined, returnTo),         A,     R, CV, DR    );
  use(() => respond,                                        A,     R            );
  use(() => processResponseTypes,                           A,     R            );
  use(() => deviceAuthorizationResponse,                       DA               );
  use(() => deviceUserFlowResponse,                                   CV, DR    );
  use(() => requestObjectResponse,                                            RO);
  /* eslint-enable no-multi-spaces, space-in-parens */

  return stack;
};
