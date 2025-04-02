import instance from './weak_cache.js';
import isPlainObject from './_/is_plain_object.js';
import { InvalidClientMetadata } from './errors.js';

function addStatic(metadata) {
  const { staticClients } = instance(this);
  if (!isPlainObject(metadata) || !metadata.client_id) {
    throw new InvalidClientMetadata('client_id is mandatory property for statically configured clients');
  }

  if (staticClients.has(metadata.client_id)) {
    throw new InvalidClientMetadata('client_id must be unique amongst statically configured clients');
  }

  staticClients.set(metadata.client_id, structuredClone(metadata));
}

export default function initializeClients(clients = []) {
  clients.map(addStatic, this);
}
