import * as jose from 'jose';

import certificateThumbprint from '../helpers/certificate_thumbprint.js';
import { InvalidRequest, InvalidTarget } from '../helpers/errors.js';
import instance from '../helpers/weak_cache.js';

export async function checkSessionBinding(provider, token, options) {
  const ignoreSessionBinding = options && options.ignoreSessionBinding === true;
  if (!token?.expiresWithSession || ignoreSessionBinding) {
    return token;
  }

  const session = await provider.Session.findByUid(token.sessionUid);
  if (!session
      || token.accountId !== session.accountId
      || token.grantId !== session.grantIdFor(token.clientId)) {
    return undefined;
  }

  return token;
}

export function validatePolicies(provider, policies) {
  if (!Array.isArray(policies)) {
    throw new TypeError('policies must be an array');
  }
  if (!policies.length) {
    throw new TypeError('policies must not be empty');
  }
  policies.forEach((policy) => {
    if (typeof policy !== 'string') {
      throw new TypeError('policies must be strings');
    }
    if (!instance(provider).features.registration.policies[policy]) {
      throw new TypeError(`policy ${policy} not configured`);
    }
  });
}

export async function setAttestBinding(token, ctx) {
  const { cnf: { jwk } } = jose.decodeJwt(ctx.get('oauth-client-attestation'));
  token.attestationJkt = await jose.calculateJwkThumbprint(jwk);
}

export function setThumbprint(token, prop, input) {
  switch (prop) {
    case 'x5t':
      if (token.jkt) {
        throw new InvalidRequest('multiple proof-of-possession mechanisms are not allowed');
      }
      token['x5t#S256'] = certificateThumbprint(input);
      break;
    case 'jkt':
      if (token['x5t#S256']) {
        throw new InvalidRequest('multiple proof-of-possession mechanisms are not allowed');
      }
      token.jkt = input;
      break;
    default:
      throw new Error('unsupported');
  }
}

export function setAudience(token, audience) {
  if (Array.isArray(audience)) {
    if (audience.length === 0) {
      return;
    }
    if (audience.length > 1) {
      throw new InvalidTarget('only a single audience value is supported');
    }

    [audience] = audience;
  } else if (typeof audience !== 'string' || !audience) {
    throw new InvalidTarget();
  }

  token.aud = audience;
}
