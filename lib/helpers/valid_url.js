import { URL } from 'node:url';

export function isHttpsUri(uri) {
  try {
    const { protocol } = new URL(uri);
    return protocol === 'https:';
  } catch (err) {
    return false;
  }
}

export function isWebUri(uri) {
  try {
    const { protocol } = new URL(uri);
    return protocol === 'https:' || protocol === 'http:';
  } catch (err) {
    return false;
  }
}
