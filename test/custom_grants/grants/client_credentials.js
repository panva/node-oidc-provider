import { errors } from '../../../lib/index.js';
import {
  applyAuthorizationDetails,
  applySenderConstraints,
  buildTokenResponse,
  resolveRequestedResources,
  validateClientScope,
  validateSenderConstraints,
} from '../../../lib/helpers/grants.js';

import {
  asScopes,
  ensureScopeSubset,
  ensureSingleResource,
  scopeString,
} from './shared.js';

export const grantType = 'client_credentials';

export const parameters = new Set(['authorization_details', 'resource', 'scope']);

export const duplicates = new Set(['resource']);

export function register(provider, { authorize } = {}) {
  provider.registerGrantType(grantType, async (ctx) => {
    const requestedScopes = asScopes(ctx.oidc.params.scope);
    await validateClientScope(provider, ctx, requestedScopes);

    const resourceServers = await resolveRequestedResources(provider, ctx);
    const resourceServer = ensureSingleResource(resourceServers);
    let effectiveScopes = requestedScopes;

    if (authorize) {
      effectiveScopes = asScopes(await authorize(ctx, {
        requestedScopes,
        resourceServer,
      }));
      ensureScopeSubset(effectiveScopes, requestedScopes);
    }

    if (resourceServer) {
      effectiveScopes = new Set(
        [...effectiveScopes].filter((scope) => resourceServer.scopes.has(scope)),
      );
    }

    const constraints = await validateSenderConstraints(provider, ctx, errors.InvalidGrant);
    const token = new provider.ClientCredentials({
      client: ctx.oidc.client,
      resourceServer,
      scope: scopeString(effectiveScopes),
    });

    await applyAuthorizationDetails(provider, ctx, token);
    await applySenderConstraints(provider, ctx, token, constraints, errors.InvalidGrant);

    ctx.oidc.entity('ClientCredentials', token);
    const accessToken = await token.save();

    ctx.body = buildTokenResponse(provider, {
      accessToken,
      authorizationDetails: token.rar,
      expiresIn: token.expiration,
      scope: token.scope,
      tokenType: token.tokenType,
    });
  }, parameters, duplicates);
}
