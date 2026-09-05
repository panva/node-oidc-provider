import { randomUUID } from 'node:crypto';

import { errors } from '../../../lib/index.js';
import {
  applyAuthorizationDetails,
  buildTokenResponse,
  checkDpopReplay,
  checkDpopRequired,
  checkMtlsCert,
  findAccount,
  resolveRequestedResources,
  validateClientScope,
  validateDpop,
} from '../../../lib/helpers/grants.js';

import {
  applyAuthorizationDetailsPolicy,
  asArray,
  asScopes,
  assertNormalizedAssertion,
  assertionResources as normalizeAssertionResources,
  assertionScopes as normalizeAssertionScopes,
  authorizationDetails,
  checkBindingConflicts,
  ensureScopeSubset,
  ensureSingleResource,
  identifiers,
  invalidGrant,
  requireString,
  reserveReplay,
  scopeString,
} from './shared.js';

export const grantType = 'urn:ietf:params:oauth:grant-type:saml2-bearer';

export const parameters = new Set(['assertion', 'authorization_details', 'resource', 'scope']);

export const duplicates = new Set(['resource']);

// verifyAssertion is the trust boundary: it must securely parse XML, verify the
// XML Signature and bearer confirmation, then return only normalized values.
export function register(provider, {
  accessTokenLifetime = 300,
  audience = provider.issuer,
  authorizationDetailsPolicy,
  authorize,
  mapSubject = (_ctx, assertion) => assertion.subject,
  rejectReplay = false,
  trustedIssuers,
  verifyAssertion,
} = {}) {
  if (typeof verifyAssertion !== 'function') {
    throw new TypeError('verifyAssertion must be a function');
  }

  const replayed = new Map();

  provider.registerGrantType(grantType, async (ctx) => {
    const encoded = requireString(ctx.oidc.params, 'assertion', errors.InvalidGrant);
    let assertion;
    let assertionResources;
    let assertionScopes;

    try {
      assertion = await verifyAssertion(ctx, encoded);
      assertNormalizedAssertion(assertion);

      const assertionAudiences = asArray(assertion.audiences);
      if (assertionAudiences.some((value) => typeof value !== 'string' || !value)) {
        throw new TypeError('assertion audiences must contain non-empty strings');
      }
      assertionScopes = normalizeAssertionScopes(assertion.scope);
      assertionResources = normalizeAssertionResources(assertion.resource);

      if (trustedIssuers && !trustedIssuers.has(assertion.issuer)) {
        throw new Error('untrusted assertion issuer');
      }
      if (!assertionAudiences.includes(audience)) {
        throw new Error('assertion audience validation failed');
      }
      if (assertion.expiresAt <= Math.floor(Date.now() / 1000)) {
        throw new Error('assertion is expired');
      }
      if (assertion.clientId && assertion.clientId !== ctx.oidc.client.clientId) {
        throw new Error('assertion client mismatch');
      }
    } catch (cause) {
      throw invalidGrant(cause);
    }

    const replayKey = typeof assertion.assertionId === 'string'
      ? `${assertion.issuer}:${assertion.assertionId}`
      : undefined;

    let accountId;
    try {
      accountId = await mapSubject(ctx, assertion);
      if (typeof accountId !== 'string' || !accountId) {
        throw new TypeError('subject mapping did not return an account identifier');
      }
    } catch (cause) {
      throw invalidGrant(cause);
    }

    let effectiveScopes = ctx.oidc.params.scope === undefined
      ? assertionScopes
      : asScopes(ctx.oidc.params.scope);
    ensureScopeSubset(effectiveScopes, assertionScopes, errors.InvalidGrant);
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
      assertionAuthorizationDetails = authorizationDetails(assertion.authorizationDetails);
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
          assertion,
          authorizationDetails: sourceAuthorizationDetails,
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
    const account = await findAccount(provider, ctx, accountId, assertion);
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
      scope: assertion.scope,
      scopes: effectiveScopes,
    };
    const remaining = assertion.expiresAt - Math.floor(Date.now() / 1000);
    const token = new provider.AccessToken({
      accountId: account.accountId,
      client: ctx.oidc.client,
      expiresIn: Math.min(accessTokenLifetime, remaining),
      grantId,
      gty: grantType,
      resourceServer,
      scope: scopeString(effectiveScopes),
    });
    token.assertionIssuer = assertion.issuer;
    token.actor = assertion.act;

    const dPoP = await validateDpop(provider, ctx);
    const certificate = checkMtlsCert(provider, ctx, errors.InvalidGrant);
    checkDpopRequired(provider, ctx, dPoP, errors.InvalidGrant);
    const constraints = { certificate, dPoP };
    checkBindingConflicts(constraints, errors.InvalidGrant);
    if (assertion.cnf?.jkt) {
      if (!constraints.dPoP || constraints.dPoP.thumbprint !== assertion.cnf.jkt) {
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
        replayReservation = reserveReplay(
          replayed,
          replayKey,
          'assertion ID',
          assertion.expiresAt,
        );
      } catch (cause) {
        throw invalidGrant(cause);
      }
    }

    let accessToken;
    try {
      checkBindingConflicts(constraints, errors.InvalidGrant, token);
      if (constraints.certificate) {
        token.setThumbprint('x5t', constraints.certificate);
      }
      if (constraints.dPoP) {
        await checkDpopReplay(provider, ctx, constraints.dPoP, ctx.oidc.client.clientId, errors.InvalidGrant);
        token.setThumbprint('jkt', constraints.dPoP.thumbprint);
      }
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
