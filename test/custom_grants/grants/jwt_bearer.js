import { randomUUID } from 'node:crypto';

import {
  decodeJwt,
  jwtVerify,
} from 'jose';

import { errors } from '../../../lib/index.js';
import {
  applyAuthorizationDetails,
  applySenderConstraints,
  buildTokenResponse,
  findAccount,
  resolveRequestedResources,
  validateClientScope,
  validateSenderConstraints,
} from '../../../lib/helpers/grants.js';

import {
  applyAuthorizationDetailsPolicy,
  asScopes,
  assertionResources as normalizeAssertionResources,
  assertionScopes as normalizeAssertionScopes,
  authorizationDetails,
  ensureScopeSubset,
  ensureSingleResource,
  identifiers,
  invalidGrant,
  requireString,
  reserveReplay,
  scopeString,
} from './shared.js';

export const grantType = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

export const parameters = new Set(['assertion', 'authorization_details', 'resource', 'scope']);

export const duplicates = new Set(['resource']);

function getTrust(trustedIssuers, issuer) {
  const trust = trustedIssuers instanceof Map
    ? trustedIssuers.get(issuer)
    : trustedIssuers?.[issuer];

  if (!trust) {
    throw new Error('untrusted assertion issuer');
  }

  return trust;
}

export function register(provider, {
  accessTokenLifetime = 300,
  algorithms = ['ES256'],
  audience = provider.issuer,
  authorizationDetailsPolicy,
  authorize,
  mapSubject = (_ctx, payload) => payload.sub,
  rejectReplay = false,
  requiredTyp,
  trustedIssuers,
  validateClaims,
} = {}) {
  const replayed = new Map();

  provider.registerGrantType(grantType, async (ctx) => {
    const assertion = requireString(ctx.oidc.params, 'assertion', errors.InvalidGrant);
    let payload;
    let protectedHeader;
    let trust;
    let assertionResources;
    let assertionScopes;

    try {
      const decoded = decodeJwt(assertion);
      trust = getTrust(trustedIssuers, decoded.iss);
      ({ payload, protectedHeader } = await jwtVerify(assertion, trust.key ?? trust, {
        algorithms: trust.algorithms ?? algorithms,
        audience,
        issuer: decoded.iss,
        requiredClaims: ['iss', 'sub', 'aud', 'exp'],
        typ: requiredTyp,
      }));

      if (typeof payload.sub !== 'string' || !payload.sub) {
        throw new TypeError('sub must be a non-empty string');
      }
      if (payload.jti !== undefined && (typeof payload.jti !== 'string' || !payload.jti)) {
        throw new TypeError('jti must be a non-empty string');
      }

      assertionScopes = normalizeAssertionScopes(payload.scope);
      assertionResources = normalizeAssertionResources(payload.resource);

      await validateClaims?.(ctx, payload, protectedHeader);
    } catch (cause) {
      throw invalidGrant(cause);
    }

    const replayKey = typeof payload.jti === 'string'
      ? `${payload.iss}:${payload.jti}`
      : undefined;

    let accountId;
    try {
      accountId = await mapSubject(ctx, payload, protectedHeader);
      if (typeof accountId !== 'string' || !accountId) {
        throw new TypeError('subject mapping did not return an account identifier');
      }
    } catch (cause) {
      throw invalidGrant(cause);
    }

    let effectiveScopes = ctx.oidc.params.scope === undefined
      ? assertionScopes
      : asScopes(ctx.oidc.params.scope);
    try {
      ensureScopeSubset(effectiveScopes, assertionScopes, errors.InvalidGrant);
    } catch (cause) {
      throw cause instanceof errors.InvalidGrant ? cause : invalidGrant(cause);
    }
    await validateClientScope(provider, ctx, effectiveScopes);

    const usedAssertionResources = ctx.oidc.params.resource === undefined
      && assertionResources.length !== 0;
    if (ctx.oidc.params.resource === undefined && assertionResources.length) {
      ctx.oidc.params.resource = assertionResources.length === 1
        ? assertionResources[0]
        : assertionResources;
    }

    let resourceServers;
    try {
      resourceServers = await resolveRequestedResources(provider, ctx);
    } catch (cause) {
      if (usedAssertionResources) {
        throw invalidGrant(cause);
      }
      throw cause;
    }
    for (const identifier of identifiers(resourceServers)) {
      if (!assertionResources.includes(identifier)) {
        throw invalidGrant(new Error('requested resource exceeds the assertion authorization'));
      }
    }

    let assertionAuthorizationDetails;
    let sourceAuthorizationDetails;
    try {
      assertionAuthorizationDetails = authorizationDetails(payload.authorization_details);
      sourceAuthorizationDetails = await applyAuthorizationDetailsPolicy(
        ctx,
        authorizationDetailsPolicy,
        authorizationDetails(ctx.oidc.params.authorization_details),
        assertionAuthorizationDetails,
      );
    } catch (cause) {
      throw invalidGrant(cause);
    }

    if (authorize) {
      try {
        const result = await authorize(ctx, {
          authorizationDetails: sourceAuthorizationDetails,
          payload,
          protectedHeader,
          resourceServers,
          scopes: effectiveScopes,
        });

        if (result) {
          effectiveScopes = asScopes(result.scopes ?? effectiveScopes);
          resourceServers = result.resourceServers ?? resourceServers;
          sourceAuthorizationDetails = result.authorizationDetails ?? sourceAuthorizationDetails;
        }
      } catch (cause) {
        throw invalidGrant(cause);
      }
    }

    try {
      ensureScopeSubset(effectiveScopes, assertionScopes, errors.InvalidGrant);
      for (const identifier of identifiers(resourceServers)) {
        if (!assertionResources.includes(identifier)) {
          throw new Error('authorized resource exceeds the assertion authorization');
        }
      }
      sourceAuthorizationDetails = await applyAuthorizationDetailsPolicy(
        ctx,
        authorizationDetailsPolicy,
        sourceAuthorizationDetails,
        assertionAuthorizationDetails,
      );
    } catch (cause) {
      throw cause instanceof errors.InvalidGrant ? cause : invalidGrant(cause);
    }

    const resourceServer = ensureSingleResource(resourceServers);
    const account = await findAccount(provider, ctx, accountId, payload);
    if (!account) {
      throw invalidGrant(new Error('mapped account not found'));
    }

    const grantId = randomUUID();
    const grant = new provider.Grant({
      accountId: account.accountId,
      clientId: ctx.oidc.client.clientId,
      jti: grantId,
    });
    if (resourceServer) {
      grant.addResourceScope(resourceServer.identifier(), effectiveScopes);
    } else {
      grant.addOIDCScope(effectiveScopes);
    }
    for (const detail of sourceAuthorizationDetails ?? []) {
      grant.addRar(detail);
    }
    const source = {
      accountId: account.accountId,
      grantId,
      rar: sourceAuthorizationDetails,
      resource: identifiers(resourceServers),
      scope: payload.scope,
      scopes: effectiveScopes,
    };
    const remaining = payload.exp - Math.floor(Date.now() / 1000);
    const token = new provider.AccessToken({
      accountId: account.accountId,
      client: ctx.oidc.client,
      expiresIn: Math.min(accessTokenLifetime, remaining),
      grantId,
      gty: grantType,
      resourceServer,
      scope: scopeString(effectiveScopes),
    });
    token.assertionIssuer = payload.iss;
    token.actor = payload.act;

    const constraints = await validateSenderConstraints(provider, ctx, errors.InvalidGrant);
    if (payload.cnf?.jkt) {
      if (!constraints.dPoP || constraints.dPoP.thumbprint !== payload.cnf.jkt) {
        throw invalidGrant(new Error('assertion proof-of-possession key mismatch'));
      }
    }

    await applyAuthorizationDetails(provider, ctx, token, source);
    try {
      token.rar = await applyAuthorizationDetailsPolicy(
        ctx,
        authorizationDetailsPolicy,
        token.rar,
        sourceAuthorizationDetails,
        'intersection',
      );
    } catch (cause) {
      throw invalidGrant(cause);
    }

    let replayReservation;
    if (rejectReplay) {
      try {
        replayReservation = reserveReplay(replayed, replayKey, 'assertion jti', payload.exp);
      } catch (cause) {
        throw invalidGrant(cause);
      }
    }

    let accessToken;
    try {
      await applySenderConstraints(provider, ctx, token, constraints, errors.InvalidGrant);
      ctx.oidc.entity('Account', account);
      ctx.oidc.entity('Grant', grant);
      ctx.oidc.entity('AccessToken', token);
      await grant.save();
      accessToken = await token.save();
      replayReservation?.commit();
    } catch (cause) {
      replayReservation?.rollback();
      throw cause;
    }

    ctx.body = buildTokenResponse(provider, {
      accessToken,
      authorizationDetails: token.rar,
      expiresIn: token.expiration,
      parameters: resourceServer ? { resource: resourceServer.identifier() } : undefined,
      scope: token.scope,
      tokenType: token.tokenType,
    });
  }, parameters, duplicates);
}
