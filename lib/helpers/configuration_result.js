import isPlainObject from './_/is_plain_object.js';

function invalid(path, expected) {
  return new TypeError(`${path} must ${expected}`);
}

function ignoreThenableRejection(value) {
  if (value !== null && (typeof value === 'object' || typeof value === 'function')) {
    if (typeof value.then === 'function') {
      Promise.resolve(value).catch(() => {});
    }
  }
}

export function boolean(value, path) {
  if (typeof value !== 'boolean') {
    ignoreThenableRejection(value);
    throw invalid(path, 'return a Boolean');
  }

  return value;
}

export function positiveInteger(value, path) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    ignoreThenableRejection(value);
    throw invalid(path, 'return a positive integer');
  }

  return value;
}

export function account(value, path = 'findAccount') {
  if (value === undefined) {
    return value;
  }

  if (
    value === null
    || typeof value !== 'object'
    || typeof value.accountId !== 'string'
    || value.accountId.length === 0
    || typeof value.claims !== 'function'
  ) {
    throw invalid(path, 'return undefined or an object with a non-empty accountId and a claims function');
  }

  return value;
}

export function resourceServer(value, path = 'features.resourceIndicators.getResourceServerInfo') {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw invalid(path, 'return an object');
  }

  if (typeof value.scope !== 'string') {
    throw invalid(path, 'return an object with a scope string');
  }

  if (value.audience !== undefined && typeof value.audience !== 'string') {
    throw invalid(path, 'return an object whose audience is a string when provided');
  }

  if (value.accessTokenTTL !== undefined) {
    positiveInteger(value.accessTokenTTL, `${path}.accessTokenTTL`);
  }

  if (
    value.accessTokenFormat !== undefined
    && !['opaque', 'jwt'].includes(value.accessTokenFormat)
  ) {
    throw invalid(path, 'return an object whose accessTokenFormat is "opaque" or "jwt" when provided');
  }

  return value;
}

export function extraTokenClaims(value, path = 'extraTokenClaims') {
  if (value !== undefined && !isPlainObject(value)) {
    throw invalid(path, 'return undefined or a plain object');
  }

  return value;
}
