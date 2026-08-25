import { resolveRequestedResources as resolveResources } from '../shared/check_resource.js';
import assertProviderContext from './assert_provider_context.js';
import { resourceServer as validateResourceServer } from './configuration_result.js';
import { InvalidScope } from './errors.js';
import normalizeAuthorizationDetails from './normalize_authorization_details.js';
import resolveResource from './resolve_resource.js';
import instance from './weak_cache.js';

export function validateClientScope(provider, ctx, scopes = ctx.oidc.requestParamScopes) {
  assertProviderContext(provider, ctx);

  if (typeof scopes === 'string') {
    scopes = new Set(scopes.split(' '));
  } else if (!(scopes instanceof Set)) {
    scopes = new Set(scopes);
  }

  const { client } = ctx.oidc;
  if (client.scope) {
    const allowList = new Set(client.scope.split(' '));
    const statics = instance(provider).configuration.scopes;

    for (const scope of scopes) {
      if (statics.has(scope) && !allowList.has(scope)) {
        throw new InvalidScope('requested scope is not allowed', scope);
      }
    }
  }

  return scopes;
}

export function resolveRequestedResources(provider, ctx) {
  return resolveResources(provider, ctx);
}

export async function resolveAndApplyResource(provider, ctx, source, token, grant, scope) {
  assertProviderContext(provider, ctx);

  const {
    userinfo,
    resourceIndicators,
  } = instance(provider).configuration.features;

  const resource = await resolveResource(ctx, source, { userinfo, resourceIndicators }, scope);

  if (resource) {
    const resourceServerInfo = validateResourceServer(
      await resourceIndicators.getResourceServerInfo(ctx, resource, ctx.oidc.client),
    );
    token.resourceServer = new provider.ResourceServer(resource, resourceServerInfo);
    token.scope = grant.getResourceScopeFiltered(resource, scope || source.scopes);
  } else {
    token.claims = source.claims;
    token.scope = grant.getOIDCScopeFiltered(scope || source.scopes);
  }

  return resource;
}

export async function applyAuthorizationDetails(provider, ctx, token, source) {
  assertProviderContext(provider, ctx);

  if (
    ctx.oidc.params.authorization_details !== undefined
    || source?.rar !== undefined
  ) {
    const { richAuthorizationRequests } = instance(provider).configuration.features;
    token.rar = normalizeAuthorizationDetails(
      await richAuthorizationRequests.authorizationDetailsForAccessToken(
        ctx,
        token,
        source,
        ctx.oidc.params.grant_type,
      ),
    );
  }
}
