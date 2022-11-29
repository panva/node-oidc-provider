import { URL } from 'node:url';
import { strict as assert } from 'node:assert';

export function isHttpsUri(uri) {
  try {
    const { protocol } = new URL(uri);
    assert.strictEqual(protocol, 'https:');
  } catch (err) {
    return false;
  }
  return true;
}

export function isWebUri(uri) {
  try {
    const { protocol } = new URL(uri);
    assert(['https:', 'http:'].includes(protocol));
  } catch (err) {
    return false;
  }
  return true;
}
