import { errors } from '../../../lib/index.js';
import {
  applyAuthorizationDetails,
  buildTokenResponse,
  checkDpopReplay,
  checkDpopRequired,
  checkMtlsCert,
  findAccount,
  findGrantSource,
  resolveRequestedResources,
  validateClientScope,
  validateDpop,
  validateGrant,
} from '../../../lib/helpers/grants.js';

import {
  applyAuthorizationDetailsPolicy,
  asArray,
  asScopes,
  authorizationDetails,
  checkBindingConflicts,
  ensureScopeSubset,
  identifiers,
  requireString,
  scopeString,
} from './shared.js';

export const grantType = 'urn:ietf:params:oauth:grant-type:token-exchange';
export const accessTokenType = 'urn:ietf:params:oauth:token-type:access_token';

export const parameters = new Set([
  'actor_token',
  'actor_token_type',
  'audience',
  'authorization_details',
  'requested_token_type',
  'resource',
  'scope',
  'subject_token',
  'subject_token_type',
]);

export const duplicates = new Set(['audience', 'resource']);

function invalidToken(kind, cause) {
  return new errors.InvalidRequest(`${kind} token is invalid`, undefined, { cause });
}

async function defaultValidateToken(provider, ctx, value, type, kind) {
  if (type !== accessTokenType) {
    throw new errors.InvalidRequest(`${kind}_token_type is not supported`);
  }

  let token;
  try {
    token = await findGrantSource(provider, ctx, provider.AccessToken, value, `${kind} token`);
  } catch (cause) {
    throw invalidToken(kind, cause);
  }

  if (token.isExpired) {
    throw invalidToken(kind, new Error(`${kind} token is expired`));
  }

  return token;
}

async function validateTokenAuthorization(provider, ctx, token, kind) {
  try {
    const grant = token.grantId
      ? await validateGrant(provider, ctx, token.grantId)
      : undefined;
    const account = token.accountId
      ? await findAccount(provider, ctx, token.accountId, token)
      : undefined;

    if (token.accountId && !account) {
      throw new Error(`${kind} token account is no longer available`);
    }
    if (grant && token.accountId && grant.accountId !== token.accountId) {
      throw new Error(`${kind} token account does not match its grant`);
    }

    return { account, grant };
  } catch (cause) {
    throw invalidToken(kind, cause);
  }
}

function validateActorPair(params) {
  if (params.actor_token !== undefined && params.actor_token_type === undefined) {
    throw new errors.InvalidRequest('actor_token_type must be provided with actor_token');
  }

  if (params.actor_token === undefined && params.actor_token_type !== undefined) {
    throw new errors.InvalidRequest('actor_token_type must not be provided without actor_token');
  }
}

function selectAudience(resourceServer, audiences) {
  if (audiences.length > 1) {
    throw new errors.InvalidTarget('only a single audience value is supported for provider access tokens');
  }

  const audience = audiences[0];
  if (!resourceServer || !audience) {
    return audience;
  }

  if (audience !== resourceServer.audience && audience !== resourceServer.identifier()) {
    throw new errors.InvalidTarget('resource and audience identify different targets');
  }

  return undefined;
}

export function register(provider, {
  authorizationDetailsPolicy,
  authorize,
  issueToken,
  validateToken = defaultValidateToken,
} = {}) {
  provider.registerGrantType(grantType, async (ctx) => {
    const { params } = ctx.oidc;
    const subjectTokenValue = requireString(params, 'subject_token');
    const subjectTokenType = requireString(params, 'subject_token_type');
    validateActorPair(params);

    const subjectToken = await validateToken(
      provider,
      ctx,
      subjectTokenValue,
      subjectTokenType,
      'subject',
    );
    const actorToken = params.actor_token === undefined ? undefined : await validateToken(
      provider,
      ctx,
      params.actor_token,
      params.actor_token_type,
      'actor',
    );

    const { account, grant } = await validateTokenAuthorization(
      provider,
      ctx,
      subjectToken,
      'subject',
    );
    const actorAuthorization = actorToken
      ? await validateTokenAuthorization(provider, ctx, actorToken, 'actor')
      : undefined;
    if (actorToken && !actorAuthorization.account) {
      throw invalidToken('actor', new Error('actor token does not identify an account'));
    }

    const sourceScopes = asScopes(subjectToken.scope);
    let effectiveScopes = params.scope === undefined ? sourceScopes : asScopes(params.scope);
    ensureScopeSubset(effectiveScopes, sourceScopes, errors.InvalidRequest);
    await validateClientScope(provider, ctx, effectiveScopes);

    let resourceServers = await resolveRequestedResources(provider, ctx);
    let audiences = asArray(params.audience);
    const requestedResourceIdentifiers = new Set(identifiers(resourceServers));
    const requestedAudiences = new Set(audiences);
    let sourceAuthorizationDetails;
    let effectiveAuthorizationDetails;
    try {
      sourceAuthorizationDetails = authorizationDetails(subjectToken.rar);
      effectiveAuthorizationDetails = await applyAuthorizationDetailsPolicy(
        ctx,
        authorizationDetailsPolicy,
        authorizationDetails(params.authorization_details),
        sourceAuthorizationDetails,
      );
    } catch (cause) {
      throw cause instanceof errors.InvalidRequest
        ? cause
        : new errors.InvalidRequest('subject token authorization details are invalid', undefined, { cause });
    }
    const dPoP = await validateDpop(provider, ctx);
    const certificate = checkMtlsCert(provider, ctx, errors.InvalidRequest);
    checkDpopRequired(provider, ctx, dPoP, errors.InvalidRequest);
    const constraints = { certificate, dPoP };
    checkBindingConflicts(constraints, errors.InvalidRequest);

    if (authorize) {
      const result = await authorize(ctx, {
        actorAccount: actorAuthorization?.account,
        actorGrant: actorAuthorization?.grant,
        actorToken,
        audiences,
        authorizationDetails: effectiveAuthorizationDetails,
        constraints,
        requestedTokenType: params.requested_token_type,
        resourceServers,
        scopes: effectiveScopes,
        subjectToken,
      });

      if (result) {
        effectiveScopes = asScopes(result.scopes ?? effectiveScopes);
        resourceServers = result.resourceServers ?? resourceServers;
        audiences = result.audiences ?? audiences;
        effectiveAuthorizationDetails = result.authorizationDetails
          ?? effectiveAuthorizationDetails;
      }
    }

    ensureScopeSubset(effectiveScopes, sourceScopes, errors.InvalidRequest);
    for (const resource of identifiers(resourceServers)) {
      if (!requestedResourceIdentifiers.has(resource)) {
        throw new errors.InvalidTarget('authorization policy added an unrequested resource');
      }
    }
    for (const audience of audiences) {
      if (!requestedAudiences.has(audience)) {
        throw new errors.InvalidTarget('authorization policy added an unrequested audience');
      }
    }
    try {
      effectiveAuthorizationDetails = await applyAuthorizationDetailsPolicy(
        ctx,
        authorizationDetailsPolicy,
        effectiveAuthorizationDetails,
        sourceAuthorizationDetails,
      );
    } catch (cause) {
      throw new errors.InvalidRequest(
        'authorized authorization details exceed the subject token authorization',
        undefined,
        { cause },
      );
    }

    if (
      (params.requested_token_type === undefined || params.requested_token_type === accessTokenType)
      && resourceServers.length > 1
    ) {
      throw new errors.InvalidTarget(
        'only a single resource indicator value is supported for provider access tokens',
      );
    }

    if (grant) {
      for (const resourceServer of resourceServers) {
        const granted = asScopes(
          grant.getResourceScopeFiltered(resourceServer.identifier(), effectiveScopes),
        );
        ensureScopeSubset(effectiveScopes, granted, errors.InvalidRequest);
      }
    }

    const exchange = {
      actorToken,
      audiences,
      authorizationDetails: effectiveAuthorizationDetails,
      constraints,
      requestedTokenType: params.requested_token_type,
      resourceServers,
      resources: identifiers(resourceServers),
      scopes: effectiveScopes,
      subjectToken,
    };
    let issued;

    if (
      issueToken
      && params.requested_token_type !== undefined
      && params.requested_token_type !== accessTokenType
    ) {
      issued = await issueToken(ctx, exchange);
    }

    if (issued) {
      if (typeof issued.issuedTokenType !== 'string' || !issued.issuedTokenType) {
        throw new TypeError('issueToken must return a non-empty issuedTokenType');
      }

      let issuedAuthorizationDetails;
      try {
        issuedAuthorizationDetails = issued.authorizationDetails === undefined
          ? effectiveAuthorizationDetails
          : await applyAuthorizationDetailsPolicy(
            ctx,
            authorizationDetailsPolicy,
            issued.authorizationDetails,
            effectiveAuthorizationDetails,
          );
      } catch {
        throw new errors.InvalidRequest(
          'issued token authorization details exceed the exchange authorization',
        );
      }
      const body = buildTokenResponse(provider, {
        accessToken: issued.accessToken,
        authorizationDetails: issuedAuthorizationDetails,
        expiresIn: issued.expiresIn,
        issuedTokenType: issued.issuedTokenType,
        parameters: issued.parameters,
        refreshToken: issued.refreshToken,
        scope: issued.scope ?? scopeString(effectiveScopes),
        tokenType: issued.tokenType,
      });
      checkBindingConflicts(constraints, errors.InvalidRequest);
      await checkDpopReplay(
        provider,
        ctx,
        constraints.dPoP,
        ctx.oidc.client.clientId,
        errors.InvalidRequest,
      );
      if (account) {
        ctx.oidc.entity('Account', account);
      }
      if (grant) {
        ctx.oidc.entity('Grant', grant);
      }
      ctx.body = body;
      return;
    }

    if (params.requested_token_type !== undefined && params.requested_token_type !== accessTokenType) {
      throw new errors.InvalidRequest('requested_token_type is not supported');
    }

    if (resourceServers.length > 1) {
      throw new errors.InvalidTarget('only a single resource indicator value is supported for provider access tokens');
    }

    if (!subjectToken.grantId || !subjectToken.accountId) {
      throw new errors.InvalidRequest('subject token does not carry a user authorization grant');
    }

    const resourceServer = resourceServers[0];
    const audience = selectAudience(resourceServer, audiences);
    let grantedScope;

    if (resourceServer) {
      grantedScope = grant.getResourceScopeFiltered(resourceServer.identifier(), effectiveScopes);
    } else {
      grantedScope = grant.getOIDCScopeFiltered(effectiveScopes);
    }

    const grantedScopes = asScopes(grantedScope);
    ensureScopeSubset(effectiveScopes, grantedScopes, errors.InvalidRequest);

    const token = new provider.AccessToken({
      accountId: account.accountId,
      client: ctx.oidc.client,
      expiresWithSession: subjectToken.expiresWithSession,
      grantId: grant.jti,
      gty: grantType,
      resourceServer,
      scope: scopeString(grantedScopes),
      sessionUid: subjectToken.sessionUid,
      sid: subjectToken.sid,
    });

    if (audience) {
      token.setAudience(audience);
    }
    if (actorToken) {
      token.actor = { sub: actorAuthorization.account.accountId };
    }

    await applyAuthorizationDetails(provider, ctx, token, {
      rar: effectiveAuthorizationDetails,
    });
    try {
      token.rar = await applyAuthorizationDetailsPolicy(
        ctx,
        authorizationDetailsPolicy,
        token.rar,
        effectiveAuthorizationDetails,
        'intersection',
      );
    } catch {
      throw new errors.InvalidRequest(
        'issued token authorization details exceed the exchange authorization',
      );
    }
    checkBindingConflicts(constraints, errors.InvalidRequest, token);
    if (constraints.certificate) {
      token.setThumbprint('x5t', constraints.certificate);
    }
    if (constraints.dPoP) {
      await checkDpopReplay(provider, ctx, constraints.dPoP, ctx.oidc.client.clientId, errors.InvalidRequest);
      token.setThumbprint('jkt', constraints.dPoP.thumbprint);
    }

    ctx.oidc.entity('Account', account);
    ctx.oidc.entity('Grant', grant);
    ctx.oidc.entity('AccessToken', token);
    const accessToken = await token.save();

    ctx.body = buildTokenResponse(provider, {
      accessToken,
      authorizationDetails: token.rar,
      expiresIn: token.expiration,
      issuedTokenType: accessTokenType,
      scope: token.scope,
      tokenType: token.tokenType,
    });
  }, parameters, duplicates);
}
