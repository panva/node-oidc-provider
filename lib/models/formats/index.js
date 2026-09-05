import * as opaque from './opaque.js';
import * as jwt from './jwt.js';

export function generateTokenId(provider, token) {
  const format = token.resourceServer?.accessTokenFormat ?? 'opaque';
  if (format !== 'opaque' && format !== 'jwt') {
    throw new Error('invalid format resolved');
  }
  token.format = format;
  return format === 'jwt' ? jwt.generateTokenId() : opaque.generateTokenId(provider, token);
}

export async function getValueAndPayload(provider, token) {
  switch (token.format) {
    case 'opaque':
      return opaque.getValueAndPayload(provider, token);
    case 'jwt':
      return jwt.getValueAndPayload(provider, token);
    default:
      throw new Error('invalid format resolved');
  }
}
