/* eslint-disable no-param-reassign */
import sectorValidate from './sector_validate.js';

export default async function add(provider, metadata, { ctx, store, cimd } = {}) {
  const client = new provider.Client(metadata, ctx, { cimd });

  if (client.sectorIdentifierUri !== undefined) {
    await sectorValidate(provider, client);
  }

  if (!cimd && store) {
    await provider.Client.adapter.upsert(client.clientId, client.metadata());
  }
  return client;
}
