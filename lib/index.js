/* eslint-disable import/first */
// eslint-disable-next-line import/order
import * as attention from './helpers/attention.js';

const deno = typeof Deno !== 'undefined';
const bun = typeof Bun !== 'undefined';
const workerd = typeof navigator !== 'undefined' && navigator.userAgent === 'Cloudflare-Workers';

const minimal = 'Jod';
const release = globalThis.process?.release;
if (!release?.lts || release?.lts.charCodeAt(0) < minimal.charCodeAt(0) || deno || bun || workerd) {
  attention.warn('Unsupported runtime. Use Node.js v22.x LTS, or a later LTS release.');
}

import { Provider } from './provider.js';
import * as errors from './helpers/errors.js';
import * as interactionPolicy from './helpers/interaction_policy/index.js';

export default Provider;
export { errors, interactionPolicy, Provider };
export { ExternalSigningKey } from './helpers/keystore.js';
