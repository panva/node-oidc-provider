import instance from './weak_cache.js';

export default async function fetchBodyCheck(provider, purpose, response) {
  const limit = instance(provider).configuration.fetchResponseBodyLimits[purpose];

  if (!Number.isFinite(limit)) {
    return Buffer.from(await response.arrayBuffer());
  }

  const contentLength = response.headers.get('content-length');
  if (contentLength && parseInt(contentLength, 10) > limit) {
    await response.body?.cancel();
    throw new Error('response too large');
  }

  const chunks = [];
  let received = 0;
  for await (const chunk of response.body) {
    received += chunk.length;
    if (received > limit) {
      await response.body?.cancel();
      throw new Error('response too large');
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}
