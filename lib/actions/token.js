import presence from '../helpers/validate_presence.js';
import instance from '../helpers/weak_cache.js';
import isValidScope from '../helpers/is_valid_scope.js';
import {
  InvalidRequest,
  InvalidScope,
  InvalidTarget,
  UnsupportedGrantType,
} from '../helpers/errors.js';
import noCache from '../shared/no_cache.js';
import clientAuth, { getClientAuthParams } from '../shared/client_auth.js';
import { urlencoded as parseBody } from '../shared/selective_body.js';
import rejectDupes from '../shared/reject_dupes.js';
import paramsMiddleware from '../shared/assemble_params.js';
import checkRar from '../shared/check_rar.js';

const grantTypeSet = new Set(['grant_type']);

export default [
  noCache,
  parseBody,
  function assembleTokenParams(ctx, next) {
    const { grantTypeParams } = instance(ctx.oidc.provider);
    const allowList = new Set([
      ...grantTypeParams.get(undefined),
      ...getClientAuthParams(ctx),
    ]);
    return paramsMiddleware(allowList, ctx, next);
  },
  ...clientAuth,

  rejectDupes.bind(undefined, { only: grantTypeSet }),

  async function stripGrantIrrelevantParams(ctx, next) {
    const { grantTypeParams } = instance(ctx.oidc.provider);
    const authParams = getClientAuthParams(ctx);
    const grantParams = grantTypeParams.get(ctx.oidc.params.grant_type);
    if (grantParams) {
      Object.keys(ctx.oidc.params).forEach((key) => {
        if (!(authParams.has(key) || grantParams.has(key))) {
          delete ctx.oidc.params[key];
        }
      });
    }
    await next();
  },

  async function supportedGrantTypeCheck(ctx, next) {
    presence(ctx, 'grant_type');

    const supported = instance(ctx.oidc.provider).configuration.grantTypes;

    if (!supported.has(ctx.oidc.params.grant_type) || ctx.oidc.params.grant_type === 'implicit') {
      throw new UnsupportedGrantType();
    }

    await next();
  },

  async function allowedGrantTypeCheck(ctx, next) {
    if (!ctx.oidc.client.grantTypeAllowed(ctx.oidc.params.grant_type)) {
      throw new InvalidRequest('requested grant type is not allowed for this client');
    }

    await next();
  },

  async function rejectDupesOptionalExcept(ctx, next) {
    const { grantTypeDupes } = instance(ctx.oidc.provider);
    const grantType = ctx.oidc.params.grant_type;
    if (grantTypeDupes.has(grantType)) {
      return rejectDupes({ except: grantTypeDupes.get(grantType) }, ctx, next);
    }
    return rejectDupes({}, ctx, next);
  },

  async function validateScope(ctx, next) {
    if (!isValidScope(ctx.oidc.params.scope)) {
      throw new InvalidScope('scope contains invalid characters');
    }

    return next();
  },

  checkRar,

  async function ensureRarResource(ctx, next) {
    if (ctx.oidc.params.authorization_details !== undefined) {
      if (ctx.oidc.params.resource === undefined) {
        const { defaultResource } = instance(ctx.oidc.provider).features.resourceIndicators;
        ctx.oidc.params.resource = await defaultResource(ctx, ctx.oidc.client);
      }

      if (
        !ctx.oidc.params.resource
        || (
          Array.isArray(ctx.oidc.params.resource)
          && ctx.oidc.params.resource.length === 0
        )
      ) {
        throw new InvalidTarget(
          'resource indicator must be provided or defaulted to when Rich Authorization Requests are used',
        );
      }
    }

    return next();
  },

  async function callTokenHandler(ctx) {
    const grantType = ctx.oidc.params.grant_type;

    const { grantTypeHandlers } = instance(ctx.oidc.provider);

    await grantTypeHandlers.get(grantType)(ctx);
    ctx.oidc.provider.emit('grant.success', ctx);
  },
];
