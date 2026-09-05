import { errors } from '../../../lib/index.js';
import {
  applyAuthorizationDetails,
  buildTokenResponse,
  checkDpopReplay,
  checkDpopRequired,
  checkMtlsCert,
  resolveRequestedResources,
  validateClientScope,
  validateDpop,
} from '../../../lib/helpers/grants.js';

import {
  asScopes,
  checkBindingConflicts,
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

    const dPoP = await validateDpop(provider, ctx);
    const certificate = checkMtlsCert(provider, ctx, errors.InvalidGrant);
    checkDpopRequired(provider, ctx, dPoP, errors.InvalidGrant);
    const constraints = { certificate, dPoP };
    checkBindingConflicts(constraints, errors.InvalidGrant);
    const token = new provider.ClientCredentials({
      client: ctx.oidc.client,
      resourceServer,
      scope: scopeString(effectiveScopes),
    });

    await applyAuthorizationDetails(provider, ctx, token);
    checkBindingConflicts(constraints, errors.InvalidGrant, token);
    if (constraints.certificate) {
      token.setThumbprint('x5t', constraints.certificate);
    }
    if (constraints.dPoP) {
      await checkDpopReplay(provider, ctx, constraints.dPoP, ctx.oidc.client.clientId, errors.InvalidGrant);
      token.setThumbprint('jkt', constraints.dPoP.thumbprint);
    }

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
