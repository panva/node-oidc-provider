import {
  InvalidRequest,
  UnsupportedResponseMode,
  UnsupportedResponseType,
  InvalidRedirectUri,
} from '../../helpers/errors.js';
import instance from '../../helpers/weak_cache.js';
import { isFrontChannel } from '../../helpers/resolve_response_mode.js';
import presence from '../../helpers/validate_presence.js';

/*
 * Resolves and assigns params.response_mode if it was not explicitly requested. Validates id_token
 * and token containing responses do not use response_mode query.
 */
export function checkResponseMode(ctx, next) {
  const { params, client } = ctx.oidc;

  const frontChannel = isFrontChannel(params.response_type);

  const mode = ctx.oidc.responseMode;

  if (
    mode !== undefined
    && !instance(ctx.oidc.provider).responseModes.has(mode)
  ) {
    params.response_mode = undefined;
    throw new UnsupportedResponseMode();
  }

  if (!ctx.oidc.client.responseModeAllowed(mode, params.response_type, ctx.oidc.fapiProfile)) {
    throw new InvalidRequest('requested response_mode is not allowed for this client or request');
  }

  const JWT = /jwt/.test(mode);

  if (
    mode !== undefined && JWT
    && (
      /^HS/.test(client.authorizationSignedResponseAlg)
      || /^(A|dir$)/.test(client.authorizationEncryptedResponseAlg)
    )
  ) {
    try {
      client.checkClientSecretExpiration('client secret is expired, cannot issue a JWT Authorization response');
    } catch (err) {
      const [explicit] = mode === 'jwt' ? [undefined] : mode.split('.');
      params.response_mode = explicit || undefined;
      throw err;
    }
  }

  const msg = 'requested response_mode is not allowed for the requested response_type';
  if (mode === 'query' && frontChannel) {
    throw new InvalidRequest(msg);
  } else if (mode === 'query.jwt' && frontChannel && !client.authorizationEncryptedResponseAlg) {
    throw new InvalidRequest(`${msg} unless encrypted`);
  }

  return next();
}

/*
 * Validates requested response_type is supported by the provided and allowed in the client
 * configuration
 */
export function checkResponseType(ctx, next) {
  const { params } = ctx.oidc;
  const supported = instance(ctx.oidc.provider).configuration.responseTypes;

  params.response_type = [...new Set(params.response_type.split(' '))].sort().join(' ');

  if (!supported.includes(params.response_type)) {
    throw new UnsupportedResponseType();
  }

  if (!ctx.oidc.client.responseTypeAllowed(params.response_type)) {
    throw new InvalidRequest('requested response_type is not allowed for this client');
  }

  return next();
}

function allowUnregisteredUri(ctx) {
  const { pushedAuthorizationRequests } = instance(ctx.oidc.provider).features;

  return (ctx.oidc.route === 'pushed_authorization_request' || ('PushedAuthorizationRequest' in ctx.oidc.entities))
    && pushedAuthorizationRequests.allowUnregisteredRedirectUris
    && ctx.oidc.client.sectorIdentifierUri === undefined
    && ctx.oidc.client.clientAuthMethod !== 'none';
}

function validateUnregisteredUri(ctx) {
  const { redirectUris: validator } = ctx.oidc.provider.Client.Schema.prototype;

  validator.call({
    ...ctx.oidc.client.metadata(),
    invalidate(detail) {
      throw new InvalidRequest(detail.replace('redirect_uris', 'redirect_uri'));
    },
  }, [ctx.oidc.params.redirect_uri]);

  return true;
}

/*
 * Checks that provided redirect_uri is allowed
 */
export function checkRedirectUri(ctx, next) {
  if (!ctx.oidc.client.redirectUriAllowed(ctx.oidc.params.redirect_uri)) {
    if (!allowUnregisteredUri(ctx)) {
      throw new InvalidRedirectUri();
    }

    validateUnregisteredUri(ctx);
  }

  ctx.oidc.redirectUriCheckPerformed = true;

  return next();
}

/*
 * If no redirect_uri is provided and client only pre-registered one unique value it is assumed
 * to be the requested redirect_uri and used as if it was explicitly provided;
 */
export function oneRedirectUriClients(ctx, next) {
  if (!instance(ctx.oidc.provider).configuration.allowOmittingSingleRegisteredRedirectUri || ctx.oidc.isFapi('2.0')) {
    return next();
  }

  const { params, client } = ctx.oidc;

  if (params.redirect_uri === undefined && client.redirectUris.length === 1) {
    ctx.oidc.redirectUriCheckPerformed = true;
    [params.redirect_uri] = client.redirectUris;
  }

  return next();
}

/*
 * Validates presence of mandatory OAuth2.0 parameters response_type, client_id and scope.
 */
export function oauthRequired(ctx, next) {
  // Validate: required oauth params
  presence(ctx, 'response_type', 'client_id');

  return next();
}

/*
 * Validates presence of redirect_uri and conditionally nonce if specific implicit or hybrid flow
 * are used.
 * Validates that openid scope is present is OpenID Connect specific parameters are provided.
 */
export function oidcRequired(ctx, next) {
  const { params } = ctx.oidc;

  const required = new Set(['redirect_uri']);

  // Check for nonce if implicit or hybrid flow responding with id_token issued by the authorization
  // endpoint
  if (typeof params.response_type === 'string' && params.response_type.includes('id_token')) {
    required.add('nonce');
  }

  // TODO: move this to a new helper function
  if (ctx.oidc.isFapi('1.0 Final')) {
    required.add(ctx.oidc.requestParamScopes.has('openid') ? 'nonce' : 'state');
  }

  presence(ctx, ...required);

  return next();
}
