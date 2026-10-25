import { strict as assert } from 'node:assert';

import debug from './debug.js';

export default function credentialOfferDriver(configuration, runner, moduleId) {
  const offerUrl = new URL('credential-offer', `${configuration.vci.credential_issuer_url}/`);
  let lastOffer;
  let lastCheckedUpdate;

  return async ({ status }) => {
    if (status !== 'WAITING') return;

    const runtime = await runner.getModuleState({ moduleId });
    const endpoint = runtime.exposed?.credential_offer_endpoint;
    if (!endpoint || runtime.updated === lastCheckedUpdate) return;

    // The offer endpoint stays exposed during browser and callback waits. Only a
    // new offer-wait log entry means the issuer should send another offer.
    const log = await runner.getTestLog({ moduleId });
    const waiting = log.findLastIndex((entry) => entry.src === 'VCIWaitForCredentialOffer');
    if (waiting === -1) return;
    const offer = log[waiting]._id;
    assert(offer, 'credential-offer wait log entry is missing its id');
    if (offer === lastOffer) {
      lastCheckedUpdate = runtime.updated;
      return;
    }

    // The suite's exposed client_id remains the first client's id after it
    // switches to client2. Its explicit offer request identifies that switch.
    const previous = log.findLastIndex((entry, index) => (
      index < waiting && entry.src === 'VCIWaitForCredentialOffer'
    ));
    const secondClient = log.slice(previous + 1, waiting).some((entry) => (
      entry.msg?.includes('new Credential Offer for the second client')
    ));
    const client = secondClient ? configuration.client2 : configuration.client;
    assert(client?.client_id, 'credential-offer client is not configured');

    // A browser callback may have completed the module while its runtime values
    // and log were being read.
    const current = await runner.getModuleInfo({ moduleId });
    if (current.status !== 'WAITING') return;

    debug('Delivering credential offer to module %s for client %s', moduleId, client.client_id);
    const response = await fetch(offerUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ credential_offer_endpoint: endpoint, client_id: client.client_id }),
      signal: AbortSignal.timeout(30_000),
    });
    if (response.status !== 204) {
      throw new Error(`credential-offer delivery failed: ${response.status}\n${(await response.text()).slice(0, 4000)}`);
    }

    lastOffer = offer;
    lastCheckedUpdate = runtime.updated;
  };
}
