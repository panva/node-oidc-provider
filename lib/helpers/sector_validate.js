import { STATUS_CODES } from 'node:http';

import instance from './weak_cache.js';
import { InvalidClientMetadata } from './errors.js';

export default async function sectorValidate(provider, client) {
  if (!instance(provider).configuration.sectorIdentifierUriValidate(client)) {
    return;
  }

  /**
   * @type typeof fetch
   */
  const request = instance(provider).configuration.fetch;
  const response = await request(new URL(client.sectorIdentifierUri).href, {
    method: 'GET',
    headers: {
      accept: 'application/json',
    },
  }).catch((err) => {
    throw new InvalidClientMetadata('could not load sector_identifier_uri response', err.message);
  });

  if (response.status !== 200) {
    throw new InvalidClientMetadata(`unexpected sector_identifier_uri response status code, expected 200 OK, got ${response.status} ${STATUS_CODES[response.status]}`);
  }

  let body;
  try {
    body = await response.json();
  } catch (err) {
    throw new InvalidClientMetadata('failed to parse sector_identifier_uri JSON response', err.message);
  }

  try {
    if (!Array.isArray(body)) throw new Error('sector_identifier_uri must return single JSON array');
    if (client.responseTypes.length) {
      const match = client.redirectUris.every((uri) => body.includes(uri));
      if (!match) throw new Error('all registered redirect_uris must be included in the sector_identifier_uri response');
    }

    if (
      client.grantTypes.includes('urn:openid:params:grant-type:ciba')
      || client.grantTypes.includes('urn:ietf:params:oauth:grant-type:device_code')
    ) {
      if (!body.includes(client.jwksUri)) throw new Error("client's jwks_uri must be included in the sector_identifier_uri response");
    }
  } catch (err) {
    throw new InvalidClientMetadata(err.message);
  }
}
