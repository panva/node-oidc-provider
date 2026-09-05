import presence from '../../helpers/validate_presence.js';
import { InvalidRequest, UnknownUserId, InvalidRequestObject } from '../../helpers/errors.js';
import omitBy from '../../helpers/_/omit_by.js';
import { account as validateAccount } from '../../helpers/configuration_result.js';
import instance from '../../helpers/weak_cache.js';
import { checkIdTokenHint } from './claims.js';

const CLIENT_NOTIFICATION_TOKEN = /^[A-Za-z0-9._~+\x2F-]+=*$/u;

export function cibaRequired(ctx, next) {
  const required = new Set(['scope']);
  const callbackMode = ctx.oidc.client.backchannelTokenDeliveryMode !== 'poll';

  if (callbackMode) {
    required.add('client_notification_token');
  }

  presence(ctx, ...required);

  if (callbackMode) {
    const { client_notification_token: clientNotificationToken } = ctx.oidc.params;
    if (!CLIENT_NOTIFICATION_TOKEN.test(clientNotificationToken)) {
      throw new InvalidRequest('client_notification_token must be a valid Bearer token');
    }

    if (clientNotificationToken.length > 1024) {
      throw new InvalidRequest('client_notification_token must not exceed 1024 characters');
    }
  } else {
    ctx.oidc.params.client_notification_token = undefined;
  }

  return next();
}

export async function cibaLoadAccount(ctx, next) {
  const mechanisms = omitBy({
    login_hint_token: ctx.oidc.params.login_hint_token,
    id_token_hint: ctx.oidc.params.id_token_hint,
    login_hint: ctx.oidc.params.login_hint,
  }, (value) => typeof value !== 'string' || !value);

  let mechanism;
  let length;
  let value;

  try {
    ({ 0: [mechanism, value], length } = Object.entries(mechanisms));
  } catch {}

  if (!length) {
    throw new InvalidRequest('missing one of required parameters login_hint_token, id_token_hint, or login_hint');
  } else if (length !== 1) {
    throw new InvalidRequest('only one of required parameters login_hint_token, id_token_hint, or login_hint must be provided');
  }

  const { findAccount, features } = instance(ctx.oidc.provider).configuration;
  const { ciba } = features;

  let accountId;
  switch (mechanism) {
    case 'id_token_hint':
      await checkIdTokenHint(ctx, () => {});
      ({ payload: { sub: accountId } } = ctx.oidc.entities.IdTokenHint);
      break;
    case 'login_hint_token':
      accountId = await ciba.processLoginHintToken(ctx, value);
      break;
    case 'login_hint':
      accountId = await ciba.processLoginHint(ctx, value);
      break;
  }

  if (!accountId) {
    throw new UnknownUserId('could not identify end-user');
  }
  const account = validateAccount(await findAccount(ctx, accountId));
  if (!account) {
    throw new UnknownUserId('could not identify end-user');
  }
  ctx.oidc.entity('Account', account);

  await ciba.verifyUserCode(ctx, account, ctx.oidc.params.user_code);

  return next();
}

/*
 * Validates the requested_expiry parameter
 */
export function checkRequestedExpiry(ctx, next) {
  if (ctx.oidc.params.requested_expiry !== undefined) {
    const requestedExpiry = +ctx.oidc.params.requested_expiry;

    if (!Number.isSafeInteger(requestedExpiry) || Math.sign(requestedExpiry) !== 1) {
      throw new InvalidRequest('invalid requested_expiry parameter value');
    }
  }

  return next();
}

export async function checkCibaContext(ctx, next) {
  const { ciba } = instance(ctx.oidc.provider).features;

  await Promise.all([
    ciba.validateRequestContext(ctx, ctx.oidc.params.request_context),
    ciba.validateBindingMessage(ctx, ctx.oidc.params.binding_message),
  ]);

  return next();
}

export async function backchannelRequestResponse(ctx) {
  const { BackchannelAuthenticationRequest } = ctx.oidc.provider;
  const { ciba } = instance(ctx.oidc.provider).features;

  const request = new BackchannelAuthenticationRequest({
    accountId: ctx.oidc.account.accountId,
    claims: ctx.oidc.claims,
    client: ctx.oidc.client,
    nonce: ctx.oidc.params.nonce,
    params: ctx.oidc.params.toPlainObject(),
    resource: Object.keys(ctx.oidc.resourceServers),
    scope: [...ctx.oidc.requestParamScopes].join(' '),
  });

  if (ctx.oidc.client.clientAuthMethod === 'attest_jwt_client_auth') {
    await request.setAttestBinding(ctx);
  }

  switch (request.resource.length) {
    case 0:
      delete request.resource;
      break;
    case 1:
      [request.resource] = request.resource;
      break;
  }

  ctx.oidc.entity('BackchannelAuthenticationRequest', request);

  const id = await request.save();

  ctx.body = {
    expires_in: request.expiration,
    auth_req_id: id,
  };

  await ciba.triggerAuthenticationDevice(ctx, request, ctx.oidc.account, ctx.oidc.client);
}

/*
 * Remaps the Backchannel Authentication Endpoint errors thrown in downstream middlewares.
 */
async function requestObjectRemapErrors(_ctx, next) {
  return next().catch((err) => {
    if (err instanceof InvalidRequestObject) {
      Object.assign(err, {
        message: 'invalid_request',
        error: 'invalid_request',
      });
    }

    throw err;
  });
}

export { requestObjectRemapErrors as backchannelRequestRemapErrors };
