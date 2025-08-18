import sectorValidate from './sector_validate.js';

export default async function add(provider, metadata, { ctx, store = false } = {}) {
  const client = new provider.Client(metadata, ctx); // eslint-disable-line no-use-before-define

  if (client.sectorIdentifierUri !== undefined) {
    await sectorValidate(provider, client);
  }

  if (store) {
    await provider.Client.adapter.upsert(client.clientId, client.metadata());
  }
  return client;
}
