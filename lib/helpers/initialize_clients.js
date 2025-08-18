import instance from './weak_cache.js';
import isPlainObject from './_/is_plain_object.js';
import { InvalidClientMetadata } from './errors.js';

export default function initializeClients(clients = []) {
  let staticClients;

  for (const metadata of clients) {
    if (!isPlainObject(metadata) || !metadata.client_id) {
      throw new InvalidClientMetadata('client_id is mandatory property for statically configured clients');
    }

    if (staticClients?.has(metadata.client_id)) {
      throw new InvalidClientMetadata('client_id must be unique amongst statically configured clients');
    }

    staticClients ||= new Map();
    staticClients.set(metadata.client_id, structuredClone(metadata));
  }

  if (staticClients) {
    instance(this).staticClients = staticClients;
  }
}
