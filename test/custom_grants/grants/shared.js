import { errors } from '../../../lib/index.js';

export function checkBindingConflicts({ certificate, dPoP }, ErrorClass, token) {
  if (
    (certificate && dPoP)
    || (certificate && token?.jkt)
    || (dPoP && token?.['x5t#S256'])
  ) {
    throw new ErrorClass('multiple proof-of-possession mechanisms are not allowed');
  }
}

export function asArray(value) {
  if (value === undefined) {
    return [];
  }

  return Array.isArray(value) ? value : [value];
}

export function asScopes(value) {
  if (value instanceof Set) {
    return new Set(value);
  }

  if (Array.isArray(value)) {
    return new Set(value);
  }

  return new Set(value?.split(' ').filter(Boolean));
}

export function assertionScopes(value) {
  if (value !== undefined && typeof value !== 'string') {
    throw new TypeError('the assertion scope must be a string');
  }

  return asScopes(value);
}

export function assertionResources(value) {
  const resources = asArray(value);
  if (resources.some((resource) => typeof resource !== 'string' || !resource)) {
    throw new TypeError('the assertion resource must be a string or an array of strings');
  }

  return resources;
}

export function scopeString(scopes) {
  return [...scopes].join(' ') || undefined;
}

export function requireString(params, name, ErrorClass = errors.InvalidRequest) {
  const value = params[name];

  if (typeof value !== 'string' || !value) {
    throw new ErrorClass(`${name} must be provided`);
  }

  return value;
}

export function ensureScopeSubset(requested, allowed, ErrorClass = errors.InvalidScope) {
  for (const scope of requested) {
    if (!allowed.has(scope)) {
      if (ErrorClass === errors.InvalidScope) {
        throw new ErrorClass('requested scope exceeds the source authorization', scope);
      }
      throw new ErrorClass(`requested scope '${scope}' exceeds the source authorization`);
    }
  }
}

export function ensureSingleResource(resourceServers) {
  if (resourceServers.length > 1) {
    throw new errors.InvalidTarget('only a single resource indicator value is supported');
  }

  return resourceServers[0];
}

export function identifiers(resourceServers) {
  return resourceServers.map((resourceServer) => resourceServer.identifier());
}

export function authorizationDetails(value) {
  if (value === undefined) {
    return undefined;
  }

  return typeof value === 'string' ? JSON.parse(value) : value;
}

// RFC 9396 Section 6.1 defines no generic authorization-details comparison.
// The injected policy must apply the semantics of each configured type. In
// subset mode it rejects escalation; in intersection mode it may remove rights.
export async function applyAuthorizationDetailsPolicy(
  ctx,
  policy,
  requested,
  allowed,
  mode = 'subset',
) {
  if (requested === undefined && allowed === undefined) {
    return undefined;
  }

  if (typeof policy !== 'function') {
    throw new TypeError('an authorization details projection policy must be configured');
  }

  if (requested === undefined) {
    if (mode === 'intersection') {
      return undefined;
    }
    requested = allowed;
  }

  if (allowed === undefined) {
    if (mode === 'intersection') {
      return undefined;
    }
    throw new TypeError('the source does not authorize rich authorization details');
  }

  if (!Array.isArray(requested) || !Array.isArray(allowed)) {
    throw new TypeError('authorization details must be arrays');
  }

  const result = await policy(ctx, {
    allowed,
    mode,
    requested,
  });

  if (result !== undefined && !Array.isArray(result)) {
    throw new TypeError('the authorization details projection policy must return an array or undefined');
  }

  return result;
}

export function reserveReplay(replayed, key, label, expiresAt) {
  if (typeof key !== 'string' || !key) {
    throw new TypeError(`${label} is required when replay rejection is enabled`);
  }
  if (!Number.isFinite(expiresAt)) {
    throw new TypeError(`${label} expiration is required for replay rejection`);
  }

  const current = Math.floor(Date.now() / 1000);
  for (const [value, expiration] of replayed) {
    if (expiration <= current) {
      replayed.delete(value);
    }
  }

  if (replayed.has(key)) {
    throw new Error('assertion replay detected');
  }

  replayed.set(key, expiresAt);
  let committed = false;

  return {
    commit() {
      committed = true;
    },
    rollback() {
      if (!committed) {
        replayed.delete(key);
      }
    },
  };
}

export function invalidGrant(cause) {
  return new errors.InvalidGrant({ cause });
}

export function assertNormalizedAssertion(assertion) {
  if (!assertion || typeof assertion !== 'object') {
    throw new TypeError('the assertion verifier returned an invalid result');
  }

  if (typeof assertion.issuer !== 'string' || !assertion.issuer) {
    throw new TypeError('the assertion issuer is missing');
  }

  if (typeof assertion.subject !== 'string' || !assertion.subject) {
    throw new TypeError('the assertion subject is missing');
  }

  if (typeof assertion.assertionId !== 'string' || !assertion.assertionId) {
    throw new TypeError('the assertion ID is missing');
  }

  if (!Number.isFinite(assertion.expiresAt)) {
    throw new TypeError('the assertion expiration is missing');
  }
}
