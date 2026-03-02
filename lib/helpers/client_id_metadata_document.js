import { WEB_URI } from '../consts/client_attributes.js';

import instance from './weak_cache.js';
import addClient from './add_client.js';
import als from './als.js';
import { InvalidClient, InvalidClientMetadata } from './errors.js';
import fetchBodyCheck from './fetch_body_check.js';
import fetchRequest from './fetch_request.js';

const FORBIDDEN_AUTH_METHODS = new Set([
  'client_secret_basic',
  'client_secret_post',
  'client_secret_jwt',
]);

const cache = new WeakMap();

function getCache(provider) {
  let entries = cache.get(provider);
  if (!entries) {
    entries = new Map();
    cache.set(provider, entries);
  }
  return entries;
}

export function isValidClientIdUrl(id) {
  const url = URL.parse(id);

  if (!url) {
    return false;
  }

  // MUST have an "https" scheme
  if (url.protocol !== 'https:') {
    return false;
  }

  // MUST contain a path component (not just "/")
  if (!url.pathname || url.pathname === '/') {
    return false;
  }

  // MUST NOT contain single-dot or double-dot path segments
  // URL.parse normalizes dot segments, so check the raw input
  const rawPath = id.replace(/^https:\/\/[^/]*/i, '').split('?')[0].split('#')[0];
  const rawSegments = rawPath.split('/');
  if (rawSegments.some((seg) => seg === '.' || seg === '..')) {
    return false;
  }

  // MUST NOT contain a fragment component
  if (url.hash) {
    return false;
  }

  // MUST NOT contain a username or password
  if (url.username || url.password) {
    return false;
  }

  return true;
}

function parseCacheDuration(response, { min, max }) {
  let duration;

  const cacheControl = response.headers.get('cache-control');
  if (cacheControl) {
    const maxAgeMatch = cacheControl.match(/(?:^|,)\s*max-age\s*=\s*(\d+)/i);
    if (maxAgeMatch) {
      duration = parseInt(maxAgeMatch[1], 10);
    }
  }

  if (duration === undefined) {
    const expires = response.headers.get('expires');
    if (expires) {
      const expiresDate = Date.parse(expires);
      if (!Number.isNaN(expiresDate)) {
        duration = Math.floor((expiresDate - Date.now()) / 1000);
      }
    }
  }

  if (duration === undefined) {
    duration = min;
  }

  return Math.max(min, Math.min(max, duration));
}

export async function resolveClientByMetadataDocument(provider, id) {
  const {
    features: { clientIdMetadataDocument: feature },
  } = instance(provider).configuration;

  const ctx = als.getStore();

  const entries = getCache(provider);

  // Check cache
  const cached = entries.get(id);
  if (cached && cached.freshUntil > Date.now()) {
    const client = await addClient(provider, cached.properties, { store: false });
    Object.defineProperty(client, 'clientIdMetadataDocument', { value: true });

    if (!(await feature.allowClient(ctx, client))) {
      throw new InvalidClient('client is not allowed');
    }

    return client;
  }

  // Gate the fetch
  if (!(await feature.allowFetch(ctx, id))) {
    throw new InvalidClient('client_id metadata document fetch not allowed');
  }

  let response;
  try {
    response = await fetchRequest(provider, id, {
      method: 'GET',
      headers: {
        accept: 'application/json',
      },
      redirect: 'manual',
    });
  } catch (err) {
    throw new InvalidClient('client_id metadata document fetch failed', err.message);
  }

  if (response.status !== 200) {
    throw new InvalidClient('client_id metadata document fetch failed', `unexpected response status ${response.status}`);
  }

  let bodyText;
  try {
    bodyText = (await fetchBodyCheck(provider, 'client_id metadata document', response)).toString();
  } catch (err) {
    throw new InvalidClient('client_id metadata document fetch failed', err.message);
  }

  let properties;
  try {
    properties = JSON.parse(bodyText);
  } catch {
    throw new InvalidClient('client_id metadata document fetch failed', 'invalid JSON');
  }

  if (typeof properties !== 'object' || properties === null || Array.isArray(properties)) {
    throw new InvalidClientMetadata('client_id metadata document is not a JSON object');
  }

  // client_id property MUST match the URL via simple string comparison
  if (properties.client_id !== id) {
    throw new InvalidClientMetadata('client_id metadata document client_id does not match the expected value');
  }

  // token_endpoint_auth_method MUST NOT be a shared-secret method
  if (FORBIDDEN_AUTH_METHODS.has(properties.token_endpoint_auth_method)) {
    throw new InvalidClientMetadata('client_id metadata document must not use shared-secret token endpoint authentication methods');
  }

  // client_secret and client_secret_expires_at MUST NOT be present
  if ('client_secret' in properties || 'client_secret_expires_at' in properties) {
    throw new InvalidClientMetadata('client_id metadata document must not contain client_secret or client_secret_expires_at');
  }

  // URI properties MUST be absolute URIs using the https: scheme
  for (const prop of WEB_URI) {
    if (prop in properties) {
      const uri = URL.parse(properties[prop]);
      if (!uri || uri.protocol !== 'https:') {
        throw new InvalidClientMetadata(`client_id metadata document ${prop} must be an https: URL`);
      }
    }
  }

  // Compute cache TTL
  const ttl = parseCacheDuration(response, feature.cacheDuration);

  const client = await addClient(provider, properties, { store: false });

  Object.defineProperty(client, 'clientIdMetadataDocument', { value: true });

  // Cache the valid properties
  entries.set(id, {
    properties,
    freshUntil: Date.now() + (ttl * 1000),
  });

  if (!(await feature.allowClient(ctx, client))) {
    throw new InvalidClient('client is not allowed');
  }

  return client;
}
