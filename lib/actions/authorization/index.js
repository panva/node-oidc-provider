const noCache = require('../../shared/no_cache');
const bodyParser = require('../../shared/conditional_body');
const rejectDupes = require('../../shared/reject_dupes');
const paramsMiddleware = require('../../shared/assemble_params');
const sessionMiddleware = require('../../shared/session');
const instance = require('../../helpers/weak_cache');
const { PARAM_LIST } = require('../../consts');
const checkResourceFormat = require('../../shared/check_resource_format');
const getTokenAuth = require('../../shared/token_auth');

const checkClient = require('./check_client');
const checkResponseMode = require('./check_response_mode');
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
const checkPixy = require('./check_pkce');
const processResponseTypes = require('./process_response_types');
const authorizationEmit = require('./authorization_emit');
const getResume = require('./resume');
const checkClientGrantType = require('./check_client_grant_type');
const checkOpenidScope = require('./check_openid_scope');
const deviceAuthorizationResponse = require('./device_authorization_response');
const deviceAuthorizationClientId = require('./device_authorization_client_id');
const deviceUserFlow = require('./device_user_flow');
const deviceUserFlowResponse = require('./device_user_flow_response');


const _ = undefined;
const A = 'authorization';
const R = 'resume';
const DA = 'device_authorization';
const CV = 'code_verification';
const DR = 'device_resume';

const parseBody = bodyParser.bind(_, 'application/x-www-form-urlencoded');
const rejectDupeClientId = rejectDupes.bind(_, { only: new Set(['client_id']) });

module.exports = function authorizationAction(provider, endpoint) {
  const {
    features: {
      claimsParameter,
      resourceIndicators,
      webMessageResponseMode,
    },
    extraParams,
  } = instance(provider).configuration();

  const { params: authParams, middleware: tokenAuth } = getTokenAuth(provider, 'token', 'device_authorization');

  const whitelist = new Set(PARAM_LIST);

  if (webMessageResponseMode.enabled) {
    whitelist.add('web_message_uri');
    whitelist.add('web_message_target');
  }

  if (claimsParameter.enabled) {
    whitelist.add('claims');
  }

  let rejectDupesMiddleware = rejectDupes.bind(_, {});
  if (resourceIndicators.enabled) {
    whitelist.add('resource');
    rejectDupesMiddleware = rejectDupes.bind(_, { except: new Set(['resource']) });
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
  use(() => noCache,                                      A, DA, R, CV, DR);
  use(() => sessionMiddleware,                            A,     R,     DR);
  use(() => deviceUserFlow.bind(_, whitelist),                      CV, DR);
  use(() => getResume.bind(_, whitelist, returnTo),              R,     DR);
  use(() => parseBody,                                    A, DA           );
  use(() => paramsMiddleware.bind(_, authParams),            DA           );
  tokenAuth.forEach((tokenAuthMiddleware) => {
    use(() => tokenAuthMiddleware,                           DA           );
  });
  use(() => deviceAuthorizationClientId,                     DA           );
  use(() => paramsMiddleware.bind(_, whitelist),          A, DA           );
  use(() => rejectDupeClientId,                           A, DA, R, CV, DR);
  use(() => checkClient,                                  A, DA, R, CV, DR);
  use(() => oneRedirectUriClients,                        A               );
  use(() => rejectDupesMiddleware,                        A, DA           );
  use(() => checkClientGrantType,                            DA           );
  use(() => checkResponseMode,                            A               );
  use(() => oauthRequired,                                A               );
  use(() => fetchRequestUri,                              A, DA           );
  use(() => processRequestObject.bind(_, whitelist),      A, DA           );
  use(() => rejectRegistration,                           A, DA           );
  use(() => oidcRequired,                                 A               );
  use(() => assignDefaults,                               A, DA           );
  use(() => checkOpenidScope.bind(_, whitelist),          A, DA           );
  use(() => checkPrompt,                                  A, DA           );
  use(() => checkResponseType,                            A               );
  use(() => checkScope.bind(_, whitelist),                A, DA           );
  use(() => checkRedirectUri,                             A               );
  use(() => checkWebMessageUri,                           A               );
  use(() => checkResourceFormat,                          A, DA           );
  use(() => checkPixy,                                    A, DA           );
  use(() => checkClaims,                                  A, DA           );
  use(() => checkMaxAge,                                  A, DA           );
  use(() => checkIdTokenHint,                             A, DA           );
  use(() => authorizationEmit,                            A,     R, CV, DR);
  use(() => assignClaims,                                 A,     R, CV, DR);
  use(() => loadAccount,                                  A,     R, CV, DR);
  use(() => interactions.bind(_, returnTo),               A,     R, CV, DR);
  use(() => respond,                                      A,     R        );
  use(() => processResponseTypes,                         A,     R        );
  use(() => deviceAuthorizationResponse,                     DA           );
  use(() => deviceUserFlowResponse,                                 CV, DR);
  /* eslint-enable no-multi-spaces, space-in-parens */

  return stack;
};
