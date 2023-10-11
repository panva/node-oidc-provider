import * as dns from 'node:dns';
import * as http from 'node:http';
import * as https from 'node:https';

import got from 'got'; // eslint-disable-line import/no-unresolved

import pickBy from './_/pick_by.js';
import instance from './weak_cache.js';

export default async function request(options) {
  Object.assign(options, {
    url: new URL(options.url),
    headers: options.headers || {},
    https: {
      rejectUnauthorized: process.env.NODE_TLS_REJECT_UNAUTHORIZED !== '0',
    },
  });
  const {
    signal = AbortSignal.timeout(2500),
    agent = options.url.protocol === 'http:' ? http.globalAgent : https.globalAgent,
    dnsLookup = dns.lookup,
  } = instance(this).configuration('httpOptions')(new URL(options.url));
  const helperOptions = pickBy({ signal, agent, dnsLookup }, Boolean);

  if (helperOptions.signal !== undefined && !(helperOptions.signal instanceof AbortSignal)) {
    throw new TypeError('"signal" http request option must be an AbortSignal');
  }

  if (helperOptions.agent !== undefined) {
    helperOptions.agent = { [options.url.protocol.slice(0, -1)]: helperOptions.agent };
  }

  if (helperOptions.dnsLookup !== undefined && typeof helperOptions.dnsLookup !== 'function') {
    throw new TypeError('"dnsLookup" http request option must be a function');
  }

  if (helperOptions['user-agent'] !== undefined && typeof helperOptions['user-agent'] !== 'string') {
    throw new TypeError('"user-agent" http request option must be a string');
  }

  // eslint-disable-next-line no-param-reassign
  options.headers['user-agent'] = helperOptions['user-agent'];

  return got({
    ...options,
    followRedirect: false,
    retry: { limit: 0 },
    throwHttpErrors: false,
    ...helperOptions,
  });
}
