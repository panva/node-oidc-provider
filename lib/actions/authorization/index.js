import { strict as assert } from 'node:assert';

import noCache from '../../shared/no_cache.js';
import { urlencoded as parseBody } from '../../shared/selective_body.js';
import paramsMiddleware from '../../shared/assemble_params.js';
import sessionMiddleware from '../../shared/session.js';
import checkRar from '../../shared/check_rar.js';
import checkResource from '../../shared/check_resource.js';
import clientAuth, { getClientAuthParams } from '../../shared/client_auth.js';

import processRequestObject, { stripOutsideJarParams } from './process_request_object.js';
import interactions, { interactionEmit } from './interactions.js';
import respond from './respond.js';
import getResume from './resume.js';
import { checkClient, checkClientGrantType, authenticatedClientId } from './client.js';
import {
  checkResponseMode,
  oauthRequired,
  oneRedirectUriClients,
  oidcRequired,
  checkResponseType,
  checkRedirectUri,
} from './response_parameters.js';
import {
  assembleAuthorizationParams,
  rejectAuthorizationDupes,
  rejectUnsupported,
  rejectRegistration,
  checkPrompt,
  checkMaxAge,
  assignDefaults,
  checkExtraParams,
} from './request_parameters.js';
import {
  loadPushedAuthorizationRequest,
  pushedAuthorizationRequestRemapErrors,
  pushedAuthorizationRequestResponse,
} from './pushed_authorization_requests.js';
import {
  cibaRequired,
  backchannelRequestRemapErrors,
  cibaLoadAccount,
  checkRequestedExpiry,
  backchannelRequestResponse,
  checkCibaContext,
} from './ciba.js';
import { checkIdTokenHint, checkClaims, assignClaims } from './claims.js';
import { checkScope, checkOpenidScope } from './scopes.js';
import { loadAccount, loadGrant } from './session.js';
import { checkPKCE, checkDpopJkt } from './sender_constraints.js';
import {
  deviceAuthorizationResponse,
  deviceUserFlow,
  deviceUserFlowErrors,
  deviceUserFlowResponse,
} from './device.js';

const A = 'authorization';
const R = 'resume';
const DA = 'device_authorization';
const CV = 'code_verification';
const DR = 'device_resume';
const PAR = 'pushed_authorization_request';
const BA = 'backchannel_authentication';

const authRequired = new Set([DA, PAR, BA]);

function assembleClientAuthParams(ctx, next) {
  return paramsMiddleware(getClientAuthParams(ctx), ctx, next);
}

const stacks = new Map([A, R, DA, CV, DR, PAR, BA].map((endpoint) => [endpoint, undefined]));

export default function authorizationAction(endpoint) {
  assert(stacks.has(endpoint), 'invalid authorization endpoint');

  const cached = stacks.get(endpoint);
  if (cached) {
    return cached;
  }

  const stack = [];

  const use = (middleware, ...only) => {
    if (only.includes(endpoint)) {
      stack.push(middleware);
    }
  };

  use(noCache,                               A, DA, R, CV, DR, PAR, BA);
  use(sessionMiddleware,                     A,     R,     DR         );
  use(deviceUserFlowErrors,                            CV, DR         );
  use(getResume,                                    R,     DR         );
  use(deviceUserFlow,                                  CV, DR         );
  use(parseBody,                             A, DA,            PAR, BA);
  if (authRequired.has(endpoint)) {
    use(assembleClientAuthParams,               DA,            PAR, BA);
    for (const clientAuthMiddlware of clientAuth) {
      use(clientAuthMiddlware,                  DA,            PAR, BA);
    }
  }
  use(authenticatedClientId,                    DA,                 BA);
  use(assembleAuthorizationParams,           A, DA,            PAR, BA);
  use(rejectAuthorizationDupes,              A, DA,            PAR, BA);
  use(rejectUnsupported,                     A, DA,            PAR, BA);
  use(stripOutsideJarParams,                                   PAR, BA);
  use(checkClient,                           A, DA, R, CV, DR         );
  use(checkClientGrantType,                     DA,                 BA);
  use(pushedAuthorizationRequestRemapErrors,                   PAR    );
  use(backchannelRequestRemapErrors,                                BA);
  use(loadPushedAuthorizationRequest,        A                        );
  use(processRequestObject,                  A, DA,            PAR, BA);
  use(checkResponseMode,                     A,                PAR    );
  use(oneRedirectUriClients,                 A,                PAR    );
  use(oauthRequired,                         A,                PAR    );
  use(rejectRegistration,                    A, DA,            PAR, BA);
  use(checkResponseType,                     A,                PAR    );
  use(oidcRequired,                          A,                PAR    );
  use(cibaRequired,                                                 BA);
  use(assignDefaults,                        A, DA,                 BA);
  use(checkPrompt,                           A,                PAR    );
  use(checkScope,                            A, DA,            PAR, BA);
  use(checkOpenidScope,                      A, DA,            PAR, BA);
  use(checkRedirectUri,                      A,                PAR    );
  use(checkPKCE,                             A,                PAR    );
  use(checkClaims,                           A, DA,            PAR, BA);
  use(checkRar,                              A, DA,            PAR, BA);
  use(checkResource,                         A, DA, R, CV, DR, PAR, BA);
  use(checkMaxAge,                           A, DA,            PAR, BA);
  use(checkRequestedExpiry,                                         BA);
  use(checkCibaContext,                                             BA);
  use(checkIdTokenHint,                      A, DA,            PAR    );
  use(checkDpopJkt,                                            PAR    );
  use(checkExtraParams,                      A, DA,            PAR, BA);
  use(interactionEmit,                       A,     R, CV, DR         );
  use(assignClaims,                          A,     R, CV, DR,      BA);
  use(cibaLoadAccount,                                              BA);
  use(loadAccount,                           A,     R, CV, DR         );
  use(loadGrant,                             A,     R, CV, DR         );
  use(interactions,                          A,     R, CV, DR         );
  use(respond,                               A,     R                 );
  use(deviceAuthorizationResponse,              DA                    );
  use(deviceUserFlowResponse,                          CV, DR         );
  use(pushedAuthorizationRequestResponse,                      PAR    );
  use(backchannelRequestResponse,                                   BA);

  stacks.set(endpoint, stack);
  return stack;
}
