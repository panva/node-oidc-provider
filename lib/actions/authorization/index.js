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
const cibaRequired = require('./ciba_required');
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
const loadGrant = require('./load_grant');
const interactions = require('./interactions');
const respond = require('./respond');
const checkPKCE = require('./check_pkce');
const processResponseTypes = require('./process_response_types');
const interactionEmit = require('./interaction_emit');
const getResume = require('./resume');
const checkClientGrantType = require('./check_client_grant_type');
const checkOpenidScope = require('./check_openid_scope');
const deviceAuthorizationResponse = require('./device_authorization_response');
const authenticatedClientId = require('./authenticated_client_id');
const deviceUserFlow = require('./device_user_flow');
const deviceUserFlowErrors = require('./device_user_flow_errors');
const deviceUserFlowResponse = require('./device_user_flow_response');
const pushedAuthorizationRequestRemapErrors = require('./pushed_authorization_request_remap_errors');
const backchannelRequestRemapErrors = require('./backchannel_request_remap_errors');
const stripOutsideJarParams = require('./strip_outside_jar_params');
const pushedAuthorizationRequestResponse = require('./pushed_authorization_request_response');
const cibaLoadAccount = require('./ciba_load_account');
const checkRequestedExpiry = require('./check_requested_expiry');
const backchannelRequestResponse = require('./backchannel_request_response');
const checkCibaContext = require('./check_ciba_context');

const A = 'authorization';
const R = 'resume';
const DA = 'device_authorization';
const CV = 'code_verification';
const DR = 'device_resume';
const PAR = 'pushed_authorization_request';
const BA = 'backchannel_authentication';

const authRequired = new Set([DA, PAR, BA]);

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

  const allowList = new Set(PARAM_LIST);

  if (webMessageResponseMode.enabled) {
    allowList.add('web_message_uri');
    allowList.add('web_message_target');
  }

  if (claimsParameter.enabled) {
    allowList.add('claims');
  }

  let rejectDupesMiddleware = rejectDupes.bind(undefined, {});
  if (resourceIndicators.enabled) {
    allowList.add('resource');
    rejectDupesMiddleware = rejectDupes.bind(undefined, { except: new Set(['resource']) });
  }

  extraParams.forEach(Set.prototype.add.bind(allowList));
  if ([DA, CV, DR, BA].includes(endpoint)) {
    allowList.delete('web_message_uri');
    allowList.delete('web_message_target');
    allowList.delete('response_type');
    allowList.delete('response_mode');
    allowList.delete('code_challenge_method');
    allowList.delete('code_challenge');
    allowList.delete('state');
    allowList.delete('redirect_uri');
    allowList.delete('prompt');
  }

  if (endpoint === BA) {
    allowList.add('client_notification_token');
    allowList.add('login_hint_token');
    allowList.add('binding_message');
    allowList.add('user_code');
    allowList.add('request_context');
    allowList.add('requested_expiry');
  }

  const stack = [];

  const use = (middleware, ...only) => {
    if (only.includes(endpoint)) {
      stack.push(middleware());
    }
  };
  const returnTo = /^(code|device)_/.test(endpoint) ? 'device_resume' : 'resume';

  /* eslint-disable no-multi-spaces, space-in-parens */
  use(() => noCache,                                        A, DA, R, CV, DR, PAR, BA);
  use(() => sessionMiddleware,                              A,     R,     DR         );
  use(() => deviceUserFlowErrors,                                     CV, DR         );
  use(() => getResume.bind(undefined, allowList, returnTo),        R,     DR         );
  use(() => deviceUserFlow.bind(undefined, allowList),                CV, DR         );
  use(() => parseBody,                                      A, DA,            PAR, BA);
  if (authRequired.has(endpoint)) {
    const { params: authParams, middleware: tokenAuth } = getTokenAuth(provider, 'token');
    use(() => paramsMiddleware.bind(undefined, authParams),    DA,            PAR, BA);
    tokenAuth.forEach((tokenAuthMiddleware) => {
      use(() => tokenAuthMiddleware,                           DA,            PAR, BA);
    });
  }
  use(() => authenticatedClientId,                             DA,                 BA);
  use(() => paramsMiddleware.bind(undefined, allowList),    A, DA,            PAR, BA);
  use(() => stripOutsideJarParams,                                            PAR, BA);
  use(() => rejectDupesMiddleware,                          A, DA,            PAR, BA);
  use(() => rejectUnsupported,                              A, DA,            PAR, BA);
  use(() => checkClient,                                    A, DA, R, CV, DR         );
  use(() => checkClientGrantType,                              DA,                 BA);
  use(() => checkResponseMode,                              A,                PAR    );
  use(() => pushedAuthorizationRequestRemapErrors,                            PAR    );
  use(() => backchannelRequestRemapErrors,                                         BA);
  use(() => fetchRequestUri,                                A, DA                    );
  use(() => processRequestObject.bind(
    undefined, allowList, rejectDupesMiddleware,
  ),                                                        A, DA,            PAR, BA);
  use(() => oneRedirectUriClients,                          A,                PAR    );
  use(() => oauthRequired,                                  A,                PAR    );
  use(() => rejectRegistration,                             A, DA,            PAR, BA);
  use(() => checkResponseType,                              A,                PAR    );
  use(() => oidcRequired,                                   A,                PAR    );
  use(() => cibaRequired,                                                          BA);
  use(() => assignDefaults,                                 A, DA,                 BA);
  use(() => checkPrompt,                                    A,                PAR    );
  use(() => checkResource,                                  A, DA, R, CV, DR, PAR, BA);
  use(() => checkScope.bind(undefined, allowList),          A, DA,            PAR, BA);
  use(() => checkOpenidScope.bind(undefined, allowList),    A, DA,            PAR, BA);
  use(() => checkRedirectUri,                               A,                PAR    );
  use(() => checkWebMessageUri,                             A,                PAR    );
  use(() => checkPKCE,                                      A, DA,            PAR    );
  use(() => checkClaims,                                    A, DA,            PAR, BA);
  use(() => checkMaxAge,                                    A, DA,            PAR, BA);
  use(() => checkRequestedExpiry,                                                  BA);
  use(() => checkCibaContext,                                                      BA);
  use(() => checkIdTokenHint,                               A, DA,            PAR    );
  use(() => interactionEmit,                                     A,     R, CV, DR    );
  use(() => assignClaims,                                   A,     R, CV, DR,      BA);
  use(() => cibaLoadAccount,                                                       BA);
  use(() => loadAccount,                                    A,     R, CV, DR         );
  use(() => loadGrant,                                      A,     R, CV, DR         );
  use(() => interactions.bind(undefined, returnTo),         A,     R, CV, DR         );
  use(() => respond,                                        A,     R                 );
  use(() => processResponseTypes,                           A,     R                 );
  use(() => deviceAuthorizationResponse,                       DA                    );
  use(() => deviceUserFlowResponse,                                   CV, DR         );
  use(() => pushedAuthorizationRequestResponse,                               PAR    );
  use(() => backchannelRequestResponse,                                            BA);
  /* eslint-enable no-multi-spaces, space-in-parens */

  return stack;
};
