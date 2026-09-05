import {
  InvalidRequest,
  RequestNotSupported,
  RequestUriNotSupported,
  RegistrationNotSupported,
} from '../../helpers/errors.js';
import instance from '../../helpers/weak_cache.js';
import { PARAM_LIST } from '../../consts/index.js';
import assembleParams from '../../shared/assemble_params.js';
import rejectDupes from '../../shared/reject_dupes.js';

const requestParams = new WeakMap();
const nonFrontchannelRoutes = new Set([
  'device_authorization', 'code_verification', 'device_resume', 'backchannel_authentication',
]);
const frontchannelParams = [
  'web_message_uri', 'response_type', 'response_mode', 'code_challenge_method',
  'code_challenge', 'state', 'redirect_uri', 'prompt',
];
const cibaParams = [
  'client_notification_token', 'login_hint_token', 'binding_message',
  'user_code', 'request_context', 'requested_expiry',
];
const dpopRoutes = new Set(['authorization', 'resume', 'pushed_authorization_request']);
const resourceDupes = { except: new Set(['resource']) };

export function getAuthorizationParams(ctx) {
  if (requestParams.has(ctx)) {
    return requestParams.get(ctx);
  }

  const { features, extraParams } = instance(ctx.oidc.provider).configuration;
  const { route } = ctx.oidc;
  const allowList = new Set(PARAM_LIST);

  if (features.webMessageResponseMode.enabled) {
    allowList.add('web_message_uri'); // adding it just so that it can be rejected when detected
  }
  if (features.claimsParameter.enabled) allowList.add('claims');
  if (features.resourceIndicators.enabled) allowList.add('resource');
  if (features.richAuthorizationRequests.enabled) allowList.add('authorization_details');

  extraParams.forEach(Set.prototype.add.bind(allowList));

  if (nonFrontchannelRoutes.has(route)) {
    for (const param of frontchannelParams) allowList.delete(param);
  }
  if (route === 'backchannel_authentication') {
    for (const param of cibaParams) allowList.add(param);
  }
  if (features.dPoP.enabled && dpopRoutes.has(route)) allowList.add('dpop_jkt');

  requestParams.set(ctx, allowList);
  return allowList;
}

export function assembleAuthorizationParams(ctx, next) {
  return assembleParams(getAuthorizationParams(ctx), ctx, next);
}

export function rejectAuthorizationDupes(ctx, next) {
  const { resourceIndicators } = instance(ctx.oidc.provider).features;
  return rejectDupes(resourceIndicators.enabled ? resourceDupes : undefined, ctx, next);
}

/*
 * Rejects request and request_uri parameters when not supported. Also rejects wmrm's relay mode.
 */
export function rejectUnsupported(ctx, next) {
  const {
    requestObjects,
    pushedAuthorizationRequests,
    webMessageResponseMode,
  } = instance(ctx.oidc.provider).features;
  const { params } = ctx.oidc;

  if (params.request !== undefined && !requestObjects.enabled) {
    throw new RequestNotSupported();
  }

  if (
    params.request_uri !== undefined
    && (ctx.oidc.route !== 'authorization' || !pushedAuthorizationRequests.enabled)
  ) {
    throw new RequestUriNotSupported();
  }

  if (webMessageResponseMode.enabled && params.response_mode?.includes('web_message') && params.web_message_uri) {
    const error = new InvalidRequest('Web Message Response Mode Relay Mode is not supported');
    error.allow_redirect = false;
    throw error;
  }

  return next();
}

/*
 * Rejects registration parameter as not supported.
 */
export function rejectRegistration(ctx, next) {
  if (ctx.oidc.params.registration !== undefined) {
    throw new RegistrationNotSupported();
  }

  return next();
}

/*
 * assign max_age and acr_values if it is not provided explictly but is configured with default
 * values on the client
 */
export function assignDefaults(ctx, next) {
  const { params, client } = ctx.oidc;

  if (!params.acr_values && client.defaultAcrValues) {
    params.acr_values = client.defaultAcrValues.join(' ');
  }

  if (params.max_age === undefined && client.defaultMaxAge !== undefined) {
    params.max_age = client.defaultMaxAge.toString();
  }

  return next();
}

/*
 * Checks that all requested prompts are supported and validates prompt none is not combined with
 * other prompts
 */
export function checkPrompt(ctx, next) {
  if (ctx.oidc.params.prompt !== undefined) {
    const { prompts } = ctx.oidc;
    const supported = instance(ctx.oidc.provider).configuration.prompts;

    for (const prompt of prompts) {
      if (!supported.has(prompt)) {
        throw new InvalidRequest('unsupported prompt value requested');
      }
    }

    if (prompts.has('none') && prompts.size !== 1) {
      throw new InvalidRequest('prompt none must only be used alone');
    }
  }

  return next();
}

/*
 * Validates the max_age parameter and handles max_age=0 to prompt=login translation
 */
export function checkMaxAge(ctx, next) {
  if (ctx.oidc.params.max_age !== undefined) {
    const maxAge = +ctx.oidc.params.max_age;

    if (!Number.isSafeInteger(maxAge) || Math.sign(maxAge) === -1) {
      throw new InvalidRequest('invalid max_age parameter value');
    }

    if (maxAge === 0) {
      const { prompts } = ctx.oidc;
      ctx.oidc.params.max_age = undefined;
      if (!prompts.has('login')) {
        prompts.add('login');
        ctx.oidc.params.prompt = [...prompts].join(' ');
      }
    }
  }

  return next();
}

/*
 * Executes registered extraParams validators.
 */
export async function checkExtraParams(ctx, next) {
  const { extraParamsValidations } = instance(ctx.oidc.provider).configuration;

  if (!extraParamsValidations) {
    return next();
  }

  for (const [param, validator] of extraParamsValidations) {
    await validator(ctx, ctx.oidc.params[param], ctx.oidc.client);
  }

  return next();
}
